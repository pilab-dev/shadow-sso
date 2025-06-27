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
	sssogin "github.com/pilab-dev/shadow-sso/api/gin"
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

// ServerConfig now embeds the application config and holds Prometheus registry
type ServerConfig struct {
	AppConfig          appconfig.Config // Embed the main application config
	PrometheusRegistry prometheus.Registerer
}

// Start initializes and starts the ConnectRPC server.
func Start(cfg ServerConfig) error {
	log.Info().Msgf("Starting ConnectRPC server on %s", cfg.AppConfig.HTTPAddr)
	ctx := context.Background() // Use a background context for setup

	// Initialize repositories based on StorageBackend
	var tokenRepo domain.TokenRepository
	var clientRepo client.ClientStore
	var authCodeRepo domain.AuthorizationCodeRepository
	var pkceRepo domain.PkceRepository // TODO: this has been merged to authcoderepo
	var deviceAuthRepo domain.DeviceAuthorizationRepository

	var userRepo domain.UserRepository
	var sessionRepo domain.SessionRepository
	var saRepo domain.ServiceAccountRepository
	var pubKeyRepo domain.PublicKeyRepository

	// MongoDB initialization (always needed for some repositories, or conditionally)
	// For now, let's assume MongoDB is always initialized for non-token data or if it's the primary backend.
	// This could be further optimized if DTS mode means no MongoDB at all.
	log.Info().Msg("Initializing MongoDB...")
	if err := mongodb.InitMongoDB(ctx, cfg.AppConfig.MongoURI, cfg.AppConfig.MongoDBName); err != nil {
		log.Fatal().Err(err).Msg("Failed to initialize MongoDB")
		return err
	}
	defer mongodb.CloseMongoDB(ctx)
	db := mongodb.GetDB()

	// Initialize MongoDB-backed repositories first (they might be overridden for tokenRepo if DTS is used)
	_, err := mongodb.NewDatabaseIndexer(ctx, db)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to create MongoDB collection indexer")
		return err
	}

	userRepo, err = mongodb.NewUserRepositoryMongo(ctx, db)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to init UserRepositoryMongo")
		return err
	}
	sessionRepo, err = mongodb.NewSessionRepositoryMongo(ctx, db)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to init SessionRepositoryMongo")
		return err
	}
	saRepo, err = mongodb.NewServiceAccountRepositoryMongo(db) // Assuming context not needed or taken from db
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to init ServiceAccountRepositoryMongo")
		return err
	}
	pubKeyRepo, err = mongodb.NewPublicKeyRepositoryMongo(db)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to init PublicKeyRepositoryMongo")
		return err
	}
	idpRepo, err := mongodb.NewIdPRepositoryMongo(ctx, db)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to init IdPRepositoryMongo")
		return err
	}

	if cfg.AppConfig.StorageBackend == appconfig.StorageTypeDTS {
		log.Info().Msg("StorageBackend is DTS. Initializing DTS client and repositories.")
		// Initialize DTS connectrpc client
		dtsAPIClient, err := dtsclient.NewClient(dtsclient.Config{
			Address:        cfg.AppConfig.DTSClientAddress,
			ConnectTimeout: cfg.AppConfig.DTSConnectTimeout,
			// We are dialing outside NewClient now, so this might need adjustment
			// For now, assume NewClient can take an existing conn or be refactored.
			// Let's assume NewDTSClient (from previous step) is the correct one:
			// dtsAPIClient := dtsclient.NewDTSClient(dtsGrpcConn)
			// For now, let's use the constructor that takes the connection directly if available, or pass the conn to repo constructors
		})
		if err != nil { // This path might change if NewClient changes
			log.Fatal().Err(err).Msg("Failed to create DTS API Client wrapper")
			return err
		}

		// Override repositories with DTS implementations
		log.Info().Msg("Overriding repositories with DTS implementations...")
		tokenRepo = dtsclient.NewDTSTokenRepository(dtsAPIClient)
		authCodeRepo = dtsclient.NewDTSAuthorizationCodeRepository(dtsAPIClient)
		// For PkceRepository, NewDTSPkceRepository takes a defaultTTL. Get it from config.
		pkceRepo = dtsclient.NewDTSPkceRepository(dtsAPIClient, cfg.AppConfig.DTSDefaultPKCETTL)
		deviceAuthRepo = dtsclient.NewDTSDeviceAuthorizationRepository(dtsAPIClient)
		sessionRepo = dtsclient.NewDTSSessionRepository(dtsAPIClient) // sessionRepo also switched

		// ClientRepository remains MongoDB-backed as DTS doesn't handle clients.
		// So, `clientRepo` is already correctly mongoOauthRepo.

		// oauthRepo needs to be a composite if different parts come from different backends.
		// For now, individual repos are passed to services.
		// If a single oauthRepo object is absolutely needed by some service for multiple different
		// sub-interfaces, a composite struct would be required.
		// Example:
		// type compositeOAuthRepo struct {
		// 	domain.TokenRepository
		// 	domain.AuthorizationCodeRepository
		// 	domain.PkceRepository
		// 	domain.DeviceAuthorizationRepository
		// 	domain.ClientRepository // This one would be mongo
		// }
		// oauthRepo = &compositeOAuthRepo { tokenRepo, authCodeRepo, pkceRepo, deviceAuthRepo, clientRepo }
		// For now, we are not creating this composite, assuming services take specific repos they need.
		// The main `oauthRepo` variable will remain the mongo one, and services that need specific
		// DTS-backed interfaces (like TokenService needing TokenRepository) will get the DTS versions.

		log.Info().Msg("DTS repositories initialized.")

	} else {
		log.Info().Msg("StorageBackend is MongoDB. Using MongoDB for all repositories.")
		// All repos (tokenRepo, clientRepo, authCodeRepo, pkceRepo, deviceAuthRepo, sessionRepo)
		// are already correctly pointing to their MongoDB implementations via mongoOauthRepo or specific Mongo initializers.
		tokenRepo = mongodb.NewTokenRepository(db)
		clientRepo = mongodb.NewClientRepository(db)

		ar := mongodb.NewAuthCodeRepository(db)
		authCodeRepo = ar
		pkceRepo = ar
		deviceAuthRepo = mongodb.NewDeviceAuthRepository(db)
	}

	// 3. Initialize Password Hasher
	passwordHasher := auth.NewBcryptPasswordHasher(bcrypt.DefaultCost)

	// 4. Initialize Core Services
	// TokenService
	// TODO: Update TokenSigner to use cfg.AppConfig.SigningKeyPath
	// TODO: Update JWKSService to use cfg.AppConfig.KeyRotationInterval and cfg.AppConfig.SigningKeyPath
	tokenSigner := services.NewTokenSigner()
	// This needs to be replaced with actual key loading and management
	tokenSigner.AddKeySigner("temporary-secret-for-hs256-change-me") // Placeholder
	tokenCache := cache.NewMemoryTokenStore(1 * time.Minute)
	tokenService := services.NewTokenService(
		tokenRepo, // This will be either DTS or MongoDB backed
		tokenCache,
		cfg.AppConfig.IssuerURL,
		tokenSigner,
		pubKeyRepo, // Assumed MongoDB backed
		saRepo,     // Assumed MongoDB backed
		userRepo,   // Assumed MongoDB backed
	)

	// PKCEService
	pkceService := services.NewPKCEService(pkceRepo) // pkceRepo is conditional (Mongo or DTS)

	// OAuthService
	oauthService := services.NewOAuthService(
		tokenRepo,      // Conditional (Mongo or DTS)
		authCodeRepo,   // Conditional (Mongo or DTS)
		deviceAuthRepo, // Conditional (Mongo or DTS)
		clientRepo,     // Mongo-backed (from mongoOauthRepo)
		userRepo,       // Mongo-backed
		sessionRepo,    // Conditional (Mongo or DTS)
		tokenService,   // Uses conditional tokenRepo
		cfg.AppConfig.IssuerURL,
	)
	_ = pkceService  // TODO: pkceService is created but not used yet by other main services. It might be used by an OIDC provider service or directly in handlers.
	_ = oauthService // TODO: oauthService is created but not yet explicitly used to register handlers. It might be used by other services or OIDC/OAuth2 endpoint handlers.

	// *
	// * 5. Initialize Authentication Interceptor
	// *
	// TokenService for validating tokens
	authInterceptor := middleware.NewAuthInterceptor(tokenService)
	authzInterceptor := middleware.NewAuthorizationInterceptor()
	otelConnectInterceptor, err := otelconnect.NewInterceptor()
	if err != nil {
		// Log and potentially panic, or handle more gracefully depending on desired behavior
		log.Fatal().Err(err).Msg("Failed to create OpenTelemetry Connect interceptor")
		return err // Propagate error up
	}

	// * Apply interceptors: otel -> authN -> authZ
	interceptors := connect.WithInterceptors(
		otelConnectInterceptor, authInterceptor, authzInterceptor)

	// *
	// * 6. Initialize Service Implementations
	// *
	defaultKeyGen := &services.DefaultSAKeyGenerator{}
	saServer := services.NewServiceAccountServer(defaultKeyGen, saRepo, pubKeyRepo)
	userServer := services.NewUserServer(userRepo, passwordHasher)
	authServer := services.NewAuthServer(userRepo, sessionRepo, tokenService, passwordHasher)

	// *
	// * 7. Create mux and register handlers
	// *
	router := gin.New()

	saPath, saHandler := ssov1connect.NewServiceAccountServiceHandler(saServer, interceptors)
	router.Any(saPath, gin.WrapH(saHandler))
	userPath, userHandler := ssov1connect.NewUserServiceHandler(userServer, interceptors)
	router.Any(userPath, gin.WrapH(userHandler))
	authPath, authHandler := ssov1connect.NewAuthServiceHandler(authServer, interceptors)
	router.Any(authPath, gin.WrapH(authHandler))

	// * Add health check endpoints
	router.GET("/healthz", gin.WrapF(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintf(w, "OK")
	}))

	// * Add readiness check
	router.GET("/readyz", gin.WrapF(func(w http.ResponseWriter, r *http.Request) {
		// Basic readiness check: try to ping MongoDB
		// A more comprehensive check might involve other dependencies or internal states.
		if err := mongodb.Ping(ctx); err != nil {
			log.Error().Err(err).Msg("Readiness check failed: MongoDB ping failed")
			http.Error(w, "Service not ready: database connectivity issue", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintf(w, "OK")
	}))

	// * Add Prometheus metrics handler
	if cfg.PrometheusRegistry != nil {
		promHandler := promhttp.HandlerFor(
			cfg.PrometheusRegistry.(prometheus.Gatherer),
			promhttp.HandlerOpts{EnableOpenMetrics: true},
		)
		router.GET("/metrics", gin.WrapH(promHandler))
		log.Info().Msg("Prometheus metrics endpoint enabled at /metrics")
	}

	jwksService, err := services.NewJWKSService(cfg.AppConfig.KeyRotationInterval)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to create JWKSService")
	}

	clientService := client.NewClientService(clientRepo)

	// * 8. Initialize API handler and register routes
	sssogin.NewOAuth2API(&sssogin.OAuth2APIOptions{
		OAuthService:      oauthService,
		JSKSService:       jwksService,
		ClientService:     clientService,
		PkceService:       pkceService,
		Config:            ssso.NewDefaultConfig(cfg.AppConfig.IssuerURL),
		FlowStore:         oidcflow.NewInMemoryFlowStore(),
		UserSessionStore:  oidcflow.NewInMemoryUserSessionStore(),
		UserRepo:          userRepo,
		PasswordHasher:    passwordHasher,
		FederationService: federation.NewService(idpRepo, cfg.AppConfig.DefaultRedirectURI),
		TokenService:      tokenService,
	})

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
