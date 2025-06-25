package server

import (
	"context"
	// "errors" // No longer needed if all mocks using it are removed
	"net/http"
	// "os" // No longer needed for environment variables here
	"time"

	"connectrpc.com/connect"     // For connect.WithInterceptors
	"golang.org/x/crypto/bcrypt" // For bcrypt.DefaultCost
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"

	// ssso "github.com/pilab-dev/shadow-sso" // Likely no longer needed if types are moved
	"github.com/pilab-dev/shadow-sso/cache"
	"github.com/pilab-dev/shadow-sso/domain" // Ensure domain is imported
	"github.com/pilab-dev/shadow-sso/gen/proto/sso/v1/ssov1connect"
	"github.com/pilab-dev/shadow-sso/internal/auth"
	"github.com/pilab-dev/shadow-sso/middleware"
	"github.com/pilab-dev/shadow-sso/mongodb"
	"github.com/pilab-dev/shadow-sso/services"
	"github.com/rs/zerolog/log"
)

type ServerConfig struct {
	HTTPAddr    string
	MongoURI    string
	MongoDBName string
	IssuerURL   string
	// Add other fields from apps/ssso/config.go as needed, e.g.:
	// SigningKeyPath      string
	// KeyRotationInterval time.Duration
	// NextJSLoginURL string
}

// StartConnectRPCServer initializes and starts the ConnectRPC server.
func StartConnectRPCServer(cfg ServerConfig) error {
	log.Info().Msgf("Starting ConnectRPC server on %s", cfg.HTTPAddr)
	ctx := context.Background() // Use a background context for setup

	// 1. Initialize MongoDB
	// mongoURI and mongoDBName are now passed as arguments
	if err := mongodb.InitMongoDB(ctx, cfg.MongoURI, cfg.MongoDBName); err != nil {
		log.Fatal().Err(err).Msg("Failed to initialize MongoDB")
		return err
	}
	defer mongodb.CloseMongoDB(ctx)
	db := mongodb.GetDB()

	// 2. Initialize Repositories
	// NewOAuthRepository returns ssso.OAuthRepository. We need ssso.TokenRepository for TokenService.
	// Assuming ssso.OAuthRepository includes methods of ssso.TokenRepository or *mongodb.OAuthRepository implements it.
	oauthRepo, err := mongodb.NewOAuthRepository(ctx, db)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to init OAuthRepository")
		return err
	}
	// Type assertion to ensure oauthRepo can be used as domain.TokenRepository.
	// This relies on *mongodb.OAuthRepository implementing domain.TokenRepository.
	tokenRepo, ok := oauthRepo.(domain.TokenRepository)
	if !ok {
		log.Fatal().Msg("mongodb.OAuthRepository does not implement domain.TokenRepository")
	}

	pubKeyRepo, err := mongodb.NewPublicKeyRepositoryMongo(db)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to init PublicKeyRepositoryMongo")
		return err
	}
	saRepo, err := mongodb.NewServiceAccountRepositoryMongo(db)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to init ServiceAccountRepositoryMongo")
		return err
	}
	userRepo, err := mongodb.NewUserRepositoryMongo(ctx, db)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to init UserRepositoryMongo")
		return err
	}
	sessionRepo, err := mongodb.NewSessionRepositoryMongo(ctx, db)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to init SessionRepositoryMongo")
		return err
	}

	// 3. Initialize Password Hasher
	passwordHasher := auth.NewBcryptPasswordHasher(bcrypt.DefaultCost)

	// 4. Initialize TokenService
	// TODO: Update TokenSigner to use cfg.SigningKeyPath
	// TODO: Update JWKSService to use cfg.KeyRotationInterval and cfg.SigningKeyPath
	tokenSigner := services.NewTokenSigner()
	tokenSigner.AddKeySigner("temporary-secret-for-hs256-change-me") // Placeholder until RSA from file is implemented

	tokenCache := cache.NewMemoryTokenStore(1 * time.Minute)

	tokenService := services.NewTokenService(
		tokenRepo,
		tokenCache,
		cfg.IssuerURL, // Use issuerURL from config
		tokenSigner,
		pubKeyRepo,
		saRepo,
		userRepo,
	)

	// 5. Initialize Authentication Interceptor
	authInterceptor := middleware.NewAuthInterceptor(tokenService)
	authzInterceptor := middleware.NewAuthorizationInterceptor()

	// Apply interceptors: authN then authZ
	interceptors := connect.WithInterceptors(authInterceptor, authzInterceptor)

	// 6. Initialize Service Implementations
	defaultKeyGen := &services.DefaultSAKeyGenerator{}
	saServer := services.NewServiceAccountServer(defaultKeyGen, saRepo, pubKeyRepo)
	userServer := services.NewUserServer(userRepo, passwordHasher)
	authServer := services.NewAuthServer(userRepo, sessionRepo, tokenService, passwordHasher)

	// 7. Create mux and register handlers
	mux := http.NewServeMux()
	saPath, saHandler := ssov1connect.NewServiceAccountServiceHandler(saServer, interceptors)
	mux.Handle(saPath, saHandler)
	userPath, userHandler := ssov1connect.NewUserServiceHandler(userServer, interceptors)
	mux.Handle(userPath, userHandler)
	authPath, authHandler := ssov1connect.NewAuthServiceHandler(authServer, interceptors)
	mux.Handle(authPath, authHandler)

	// 8. Create and start HTTP/2 server
	srv := &http.Server{
		Addr:              cfg.HTTPAddr, // Use httpAddr from config
		Handler:           h2c.NewHandler(mux, &http2.Server{}),
		ReadHeaderTimeout: 3 * time.Second,
		ReadTimeout:       5 * time.Minute,
		WriteTimeout:      5 * time.Minute,
		MaxHeaderBytes:    8 * 1024, // 8KiB
	}
	log.Info().Msgf("ConnectRPC server listening on %s", cfg.HTTPAddr)
	return srv.ListenAndServe()
}
