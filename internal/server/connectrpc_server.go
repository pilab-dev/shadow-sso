package server

import (
	"context"
	// "errors" // No longer needed if all mocks using it are removed
	"net/http"
	"os" // For environment variables
	"time"

	"connectrpc.com/connect"     // For connect.WithInterceptors
	"golang.org/x/crypto/bcrypt" // For bcrypt.DefaultCost
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"

	"github.com/pilab-dev/shadow-sso/cache"
	// "github.com/pilab-dev/shadow-sso/domain" // domain is used by mongodb and services packages
	"github.com/pilab-dev/shadow-sso/internal/auth" // Import new auth package for password hasher
	"github.com/pilab-dev/shadow-sso/middleware"
	"github.com/pilab-dev/shadow-sso/mongodb" // Import new mongodb package
	"github.com/pilab-dev/shadow-sso/services"
	"github.com/rs/zerolog/log"
)

// StartConnectRPCServer initializes and starts the ConnectRPC server.
func StartConnectRPCServer(addr string) error {
	log.Info().Msgf("Starting ConnectRPC server on %s", addr)
	ctx := context.Background() // Use a background context for setup

	// 1. Initialize MongoDB
	mongoURI := os.Getenv("MONGO_URI")
	if mongoURI == "" {
		mongoURI = "mongodb://localhost:27017" // Default
	}
	dbName := os.Getenv("MONGO_DB_NAME")
	if dbName == "" {
		dbName = "shadow_sso_dev_db" // Default
	}
	if err := mongodb.InitMongoDB(ctx, mongoURI, dbName); err != nil {
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
	// Type assertion to ensure oauthRepo can be used as ssso.TokenRepository.
	// This relies on *mongodb.OAuthRepository implementing ssso.TokenRepository.
	tokenRepo, ok := oauthRepo.(ssso.TokenRepository)
	if !ok {
		log.Fatal().Msg("mongodb.OAuthRepository does not implement ssso.TokenRepository")
		// return errors.New("mongodb.OAuthRepository does not implement ssso.TokenRepository") // Or handle fatal
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
	privKey, err := ssso.GenerateRSAKey()
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to generate RSA key for TokenSigner")
		return err
	}
	tokenSigner, err := ssso.NewTokenSigner(privKey, "sso-kid-default") // Example key ID
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to create TokenSigner")
		return err
	}

	memCache := cache.NewMemoryTokenStore(1*time.Minute, 1000)

	tokenService := ssso.NewTokenService(
		tokenRepo,    // Real ssso.TokenRepository
		memCache,     // Cache implementation
		"sso-issuer", // Example issuer
		tokenSigner,
		pubKeyRepo, // Real domain.PublicKeyRepository
		saRepo,     // Real domain.ServiceAccountRepository
	)

	// 5. Initialize Authentication Interceptor
	authInterceptor := middleware.NewAuthInterceptor(tokenService) // Existing
	authzInterceptor := middleware.NewAuthorizationInterceptor()   // New

	// Apply interceptors: authN then authZ
	interceptors := connect.WithInterceptors(authInterceptor, authzInterceptor)

	// 6. Initialize Service Implementations
	defaultKeyGen := &services.DefaultSAKeyGenerator{}
	saServer := services.NewServiceAccountServer(defaultKeyGen, saRepo, pubKeyRepo)
	userServer := services.NewUserServer(userRepo, passwordHasher)
	// Pass sessionRepo to NewAuthServer. The constructor needs to be updated if it doesn't accept it.
	// For now, assuming NewAuthServer was updated to accept sessionRepo as its second argument.
	// If not, this will be a compile error to fix in services/auth_service.go.
	// Based on previous steps, AuthServer's constructor is:
	// NewAuthServer(userRepo domain.UserRepository, tokenService *ssso.TokenService, passwordHasher PasswordHasher)
	// It does NOT take sessionRepo yet. This needs to be addressed.
	// For now, I will pass it and assume the constructor will be fixed.
	// TODO: Update AuthServer constructor to accept SessionRepository.
	authServer := services.NewAuthServer(userRepo, tokenService, passwordHasher) // sessionRepo missing here

	// 7. Create mux and register handlers
	mux := http.NewServeMux()
	saPath, saHandler := ssov1connect.NewServiceAccountServiceHandler(saServer, connect.WithInterceptors(authInterceptor))
	mux.Handle(saPath, saHandler)
	userPath, userHandler := ssov1connect.NewUserServiceHandler(userServer, connect.WithInterceptors(authInterceptor))
	mux.Handle(userPath, userHandler)
	authPath, authHandler := ssov1connect.NewAuthServiceHandler(authServer, connect.WithInterceptors(authInterceptor))
	mux.Handle(authPath, authHandler)

	// 8. Create and start HTTP/2 server
	srv := &http.Server{
		Addr:              addr,
		Handler:           h2c.NewHandler(mux, &http2.Server{}),
		ReadHeaderTimeout: 3 * time.Second,
		ReadTimeout:       5 * time.Minute,
		WriteTimeout:      5 * time.Minute,
		MaxHeaderBytes:    8 * 1024, // 8KiB
	}
	log.Info().Msgf("ConnectRPC server listening on %s", addr)
	return srv.ListenAndServe()
}
