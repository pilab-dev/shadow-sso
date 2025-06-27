package server

import (
	"context"
	"fmt"

	// "errors" // No longer needed if all mocks using it are removed
	"net/http"
	// "os" // No longer needed for environment variables here
	"time"

	"connectrpc.com/connect"     // For connect.WithInterceptors
	"golang.org/x/crypto/bcrypt" // For bcrypt.DefaultCost
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"

	"connectrpc.com/otelconnect" // Import for OpenTelemetry Connect interceptor
	// ssso "github.com/pilab-dev/shadow-sso" // Likely no longer needed if types are moved
	"github.com/gin-gonic/gin"
	ssso "github.com/pilab-dev/shadow-sso"
	sssogin "github.com/pilab-dev/shadow-sso/api/openidv2_1"
	"github.com/pilab-dev/shadow-sso/cache"
	"github.com/pilab-dev/shadow-sso/client"
	"github.com/pilab-dev/shadow-sso/domain" // Ensure domain is imported
	"github.com/pilab-dev/shadow-sso/gen/proto/sso/v1/ssov1connect"
	"github.com/pilab-dev/shadow-sso/internal/auth"
	"github.com/pilab-dev/shadow-sso/internal/federation"
	"github.com/pilab-dev/shadow-sso/internal/oidcflow"
	"github.com/pilab-dev/shadow-sso/middleware"
	"github.com/pilab-dev/shadow-sso/mongodb"
	"github.com/pilab-dev/shadow-sso/services"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rs/zerolog/log"

	// Import the application config package
	appconfig "github.com/pilab-dev/shadow-sso/apps/ssso/config"
	"github.com/pilab-dev/shadow-sso/dtsclient"
)

// ServerConfig now includes ServiceProvider
type ServerConfig struct {
	AppConfig          appconfig.Config // Embed the main application config
	PrometheusRegistry prometheus.Registerer
	ServiceProvider    services.ServiceProvider // Added
}

// Start initializes and starts the ConnectRPC server.
func Start(cfg ServerConfig) error {
	log.Info().Msgf("Starting ConnectRPC server on %s", cfg.AppConfig.HTTPAddr)
	ctx := context.Background() // Use a background context for server lifecycle

	// ServiceProvider is now passed in cfg.ServiceProvider
	sp := cfg.ServiceProvider

	// MongoDB connection is managed by MongoRepositoryProvider,
	// which is initialized in main and its lifecycle (Disconnect) is handled there.
	// No need to call mongodb.InitMongoDB or CloseMongoDB here.

	// Repositories are no longer initialized here directly. They are accessed via sp.RepositoryProvider()
	// Services are accessed via sp.ServiceName()

	// Example: Get TokenService
	tokenService := sp.TokenService()
	if tokenService == nil {
		log.Fatal().Msg("TokenService not available from ServiceProvider")
		// return errors.New("TokenService not available") // Or panic
	}

	// Get other services as needed
	saRepo := sp.RepositoryProvider().ServiceAccountRepository(ctx) // Example if direct repo access needed
	pubKeyRepo := sp.RepositoryProvider().PublicKeyRepository(ctx)
	userRepo := sp.RepositoryProvider().UserRepository(ctx)
	sessionRepo := sp.RepositoryProvider().SessionRepository(ctx)
	passwordHasher := sp.PasswordHasher()
	// idpRepo := sp.RepositoryProvider().IdPRepository(ctx) // For FederationService if not using sp.FederationService() directly

	// *
	// * Initialize Authentication Interceptor (using TokenService from ServiceProvider)
	// *
	authInterceptor := middleware.NewAuthInterceptor(tokenService) // tokenService from SP
	authzInterceptor := middleware.NewAuthorizationInterceptor()
	otelConnectInterceptor, err := otelconnect.NewInterceptor()
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to create OpenTelemetry Connect interceptor")
		return err
	}

	interceptors := connect.WithInterceptors(
		otelConnectInterceptor, authInterceptor, authzInterceptor)

	// *
	// * Initialize Service Implementations (using services/repos from ServiceProvider)
	// *
	defaultKeyGen := &services.DefaultSAKeyGenerator{} // This could also be part of SP if configurable

	// These gRPC service implementations should ideally take service interfaces from the ServiceProvider
	// For example, NewServiceAccountServer should take a *services.ServiceAccountService
	// For now, manually constructing with repos/services from SP to minimize structural changes to existing New...Server funcs.
	// TODO: Refactor New...Server functions to take service interfaces from ServiceProvider.
	saServer := services.NewServiceAccountServer(defaultKeyGen, saRepo, pubKeyRepo)
	userServer := services.NewUserServer(userRepo, passwordHasher)
	authServer := services.NewAuthServer(userRepo, sessionRepo, tokenService, passwordHasher)


	// *
	// * Create mux and register handlers
	// *
	router := gin.New()

	saPath, saHandler := ssov1connect.NewServiceAccountServiceHandler(saServer, interceptors)
	router.Any(saPath+"/", gin.WrapH(saHandler)) // Ensure trailing slash for Connect
	userPath, userHandler := ssov1connect.NewUserServiceHandler(userServer, interceptors)
	router.Any(userPath+"/", gin.WrapH(userHandler))
	authPath, authHandler := ssov1connect.NewAuthServiceHandler(authServer, interceptors)
	router.Any(authPath+"/", gin.WrapH(authHandler))


	// * Add health check endpoints
	router.GET("/healthz", gin.WrapF(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintf(w, "OK")
	}))

	// * Add readiness check
	router.GET("/readyz", gin.WrapF(func(w http.ResponseWriter, r *http.Request) {
		// Ping the MongoDB instance via the RepositoryProvider's client if possible,
		// or add a Ping method to RepositoryProvider itself.
		// For now, this check is simplified as direct db access is removed from here.
		// A proper readiness check would involve checking critical downstream services/dependencies.
		// TODO: Implement a more robust readiness check, possibly by pinging DB via a method on ServiceProvider/RepositoryProvider
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintf(w, "OK (basic check, DB ping needs provider method)")
	}))

	// * Add Prometheus metrics handler
	if cfg.PrometheusRegistry != nil {
		promHandler := promhttp.HandlerFor(
			cfg.PrometheusRegistry.(prometheus.Gatherer), // Type assertion
			promhttp.HandlerOpts{EnableOpenMetrics: true},
		)
		router.GET("/metrics", gin.WrapH(promHandler))
		log.Info().Msg("Prometheus metrics endpoint enabled at /metrics")
	}

	// *
	// * Initialize OAuth2/OIDC API handler (sssogin.OAuth2API)
	// *
	// Get all necessary services and configurations from the ServiceProvider
	appOIDCConfig := ssso.NewDefaultConfig(cfg.AppConfig.IssuerURL) // Create the base config
	// Override with more specific settings from cfg.AppConfig if they exist in ssso.OpenIDProviderConfig structure
	appOIDCConfig.NextJSLoginURL = cfg.AppConfig.NextJSLoginURL
	appOIDCConfig.JWKSDefaultKeyRotationInterval = cfg.AppConfig.KeyRotationInterval
	// ... map other relevant fields from cfg.AppConfig to appOIDCConfig ...


	oauth2apiOptions := &sssogin.OAuth2APIOptions{
		OAuthService:      sp.OAuthService(),
		JSKSService:       sp.JWKSService(),
		ClientService:     sp.ClientService(),
		PkceService:       sp.PKCEService(),
		Config:            appOIDCConfig, // Use the fully populated OpenIDProviderConfig
		FlowStore:         sp.FlowStore(),
		UserSessionStore:  sp.UserSessionStore(),
		UserRepo:          userRepo, // UserRepo obtained from SP's RepoProvider
		PasswordHasher:    passwordHasher, // PasswordHasher from SP
		FederationService: sp.FederationService(), // Get from ServiceProvider
		TokenService:      tokenService, // TokenService from SP
	}
	oauth2api := sssogin.NewOAuth2API(oauth2apiOptions)

	// Register the OAuth2/OIDC routes
	oauth2api.RegisterRoutes(router)

	// * 9. Create and start HTTP/2 server
	srv := &http.Server{
		Addr:              cfg.AppConfig.HTTPAddr, // Use httpAddr from config
		Handler:           h2c.NewHandler(router, &http2.Server{}),
		ReadHeaderTimeout: 3 * time.Second,
		ReadTimeout:       5 * time.Minute,
		WriteTimeout:      5 * time.Minute,
		MaxHeaderBytes:    8 * 1024, // 8KiB
	}

	log.Info().Msgf("ConnectRPC server listening on %s", cfg.AppConfig.HTTPAddr)

	return srv.ListenAndServe()
}
