package server // apps/ssso-alt/internal/server

import (
	"context"
	"net/http"
	"time"

	"connectrpc.com/connect"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"

	alt_config "github.com/pilab-dev/ssso/apps/ssso-alt/config" // SSSO-Alt config types
	"github.com/pilab-dev/ssso/cache"
	"github.com/pilab-dev/ssso/domain"
	"github.com/pilab-dev/ssso/dtsclient" // DTS client and repository adapters
	"github.com/pilab-dev/ssso/gen/proto/sso/v1/ssov1connect"
	"github.com/pilab-dev/ssso/internal/auth"
	"github.com/pilab-dev/ssso/internal/oidcflow" // For OIDC flow stores
	"github.com/pilab-dev/ssso/middleware"
	"github.com/pilab-dev/ssso/mongodb" // Original MongoDB repositories
	"github.com/pilab-dev/ssso/services"
	"github.com/rs/zerolog/log"
)

// ServerConfig for ssso-alt, includes fields from alt_config.Config relevant to server startup
type ServerConfig struct {
	HTTPAddr          string
	MongoURI          string
	MongoDBName       string
	IssuerURL         string
	StorageBackend    string // "mongodb" or "dts"
	DTSClientAddress  string
	DTSConnectTimeout time.Duration
	DTSDefaultPKCETTL time.Duration
	// Add other base config fields like SigningKeyPath, KeyRotationInterval, NextJSLoginURL if needed by services
}

// StartConnectRPCServer initializes and starts the ConnectRPC server for SSSO-Alt.
func StartConnectRPCServer(cfg ServerConfig) error {
	log.Info().Msgf("Starting SSSO-Alt ConnectRPC server on %s (Backend: %s)", cfg.HTTPAddr, cfg.StorageBackend)
	ctx := context.Background()

	// --- Initialize Storage Backend ---
	var dtsCli *dtsclient.Client // DTS client, initialized if DTS backend is used

	// Repositories - these will be populated based on cfg.StorageBackend
	var tokenRepo domain.TokenRepository
	var authCodeRepo domain.AuthorizationCodeRepository
	var pkceRepo domain.PkceRepository
	var deviceAuthRepo domain.DeviceAuthorizationRepository

	// OIDC Flow Stores - these also depend on the backend
	// These are not interfaces in the current SSSO structure but concrete types.
	// We'll prepare DTS versions and they can be used where InMemory versions were used.
	var dtsFlowStore *dtsclient.DTSFlowStore
	var dtsUserSessionStore *dtsclient.DTSUserSessionStore


	if alt_config.StorageType(cfg.StorageBackend) == alt_config.StorageTypeDTS {
		log.Info().Msgf("Using DTS backend. Initializing DTS client for %s", cfg.DTSClientAddress)
		var err error
		dtsCli, err = dtsclient.NewClient(dtsclient.Config{
			Address:        cfg.DTSClientAddress,
			ConnectTimeout: cfg.DTSConnectTimeout,
			// MaxMsgSize can be added if needed from config
		})
		if err != nil {
			log.Fatal().Err(err).Msg("Failed to initialize DTS client")
			return err
		}
		defer dtsCli.Close()

		// Initialize DTS-backed repositories
		tokenRepo = dtsclient.NewDTSTokenRepository(dtsCli)
		authCodeRepo = dtsclient.NewDTSAuthorizationCodeRepository(dtsCli)
		pkceRepo = dtsclient.NewDTSPkceRepository(dtsCli, cfg.DTSDefaultPKCETTL)
		deviceAuthRepo = dtsclient.NewDTSDeviceAuthorizationRepository(dtsCli)

		dtsFlowStore = dtsclient.NewDTSFlowStore(dtsCli)
		dtsUserSessionStore = dtsclient.NewDTSUserSessionStore(dtsCli)

		log.Info().Msg("DTS-backed repositories and stores initialized.")

	} else if alt_config.StorageType(cfg.StorageBackend) == alt_config.StorageTypeMongoDB {
		log.Info().Msg("Using MongoDB backend. Initializing MongoDB.")
		if err := mongodb.InitMongoDB(ctx, cfg.MongoURI, cfg.MongoDBName); err != nil {
			log.Fatal().Err(err).Msg("Failed to initialize MongoDB")
			return err
		}
		defer mongodb.CloseMongoDB(ctx)
		db := mongodb.GetDB()

		oauthRepo, err := mongodb.NewOAuthRepository(ctx, db) // This provides multiple repo interfaces
		if err != nil {
			log.Fatal().Err(err).Msg("Failed to init MongoDB OAuthRepository")
			return err
		}
		var ok bool
		tokenRepo, ok = oauthRepo.(domain.TokenRepository)
		if !ok { log.Fatal().Msg("mongodb.OAuthRepository does not implement domain.TokenRepository") }
		authCodeRepo, ok = oauthRepo.(domain.AuthorizationCodeRepository)
		if !ok { log.Fatal().Msg("mongodb.OAuthRepository does not implement domain.AuthorizationCodeRepository") }
		pkceRepo, ok = oauthRepo.(domain.PkceRepository)
		if !ok { log.Fatal().Msg("mongodb.OAuthRepository does not implement domain.PkceRepository") }
		deviceAuthRepo, ok = oauthRepo.(domain.DeviceAuthorizationRepository)
		if !ok { log.Fatal().Msg("mongodb.OAuthRepository does not implement domain.DeviceAuthorizationRepository") }

		// For MongoDB, OIDC flow stores would be the InMemory versions or new Mongo-backed ones if they existed.
		// The original code doesn't show where these are instantiated for services.
		// Assuming services using these would default to InMemory if not otherwise specified.
		// For ssso-alt with MongoDB, we'd use InMemory as per original SSSO behavior.
		log.Info().Msg("MongoDB-backed repositories initialized. OIDC Flow/UserSession stores will use in-memory versions if not explicitly configured otherwise for services.")

	} else {
		log.Fatal().Msgf("Unsupported storage backend: %s", cfg.StorageBackend)
		// return errors.New("unsupported storage backend")
	}

	// --- Repositories that are always MongoDB-backed (or need their own DTS versions if required by spec) ---
	// For ssso-alt, these remain MongoDB backed unless explicitly stated to migrate them.
	// The problem description focuses on "token store" aspects.
	var db *mongodb.Database // Declare db variable, will be initialized if mongo is used.
	var mongoInitialized bool

	if alt_config.StorageType(cfg.StorageBackend) == alt_config.StorageTypeMongoDB {
		// MongoDB is primary, already initialized.
		db = mongodb.GetDB()
		mongoInitialized = true
	} else if alt_config.StorageType(cfg.StorageBackend) == alt_config.StorageTypeDTS {
		// DTS is primary. MongoDB might be needed for other repositories.
		// Initialize MongoDB if it's needed for User, Session, SA, PublicKey repos.
		// This assumes these repositories always use MongoDB for ssso-alt.
		log.Info().Msg("Primary backend is DTS. Initializing MongoDB for User, Session, SA, PublicKey repositories.")
		if err := mongodb.InitMongoDB(ctx, cfg.MongoURI, cfg.MongoDBName); err != nil {
			log.Fatal().Err(err).Msg("Failed to initialize MongoDB for secondary repositories")
			return err
		}
		defer mongodb.CloseMongoDB(ctx) // Close it only if DTS opened it.
		db = mongodb.GetDB()
		mongoInitialized = true
	}

	if !mongoInitialized {
		// This case should ideally not be reached if backend is correctly specified
		// and User/Session/SA/PK repos always need some DB.
		// Or, if DTS were to cover ALL repos, then Mongo wouldn't be needed.
		log.Fatal().Msg("MongoDB was not initialized, but is required for User/Session/SA/PublicKey repositories.")
		// return errors.New("mongodb not initialized for essential repositories")
	}


	pubKeyRepo, err := mongodb.NewPublicKeyRepositoryMongo(db)
	if err != nil { log.Fatal().Err(err).Msg("Failed to init PublicKeyRepositoryMongo") }
	saRepo, err := mongodb.NewServiceAccountRepositoryMongo(db)
	if err != nil { log.Fatal().Err(err).Msg("Failed to init ServiceAccountRepositoryMongo") }
	userRepo, err := mongodb.NewUserRepositoryMongo(ctx, db)
	if err != nil { log.Fatal().Err(err).Msg("Failed to init UserRepositoryMongo") }
	sessionRepo, err := mongodb.NewSessionRepositoryMongo(ctx, db) // This is domain.Session, not oidcflow.UserSession
	if err != nil { log.Fatal().Err(err).Msg("Failed to init SessionRepositoryMongo") }


	// --- Initialize Services ---
	passwordHasher := auth.NewBcryptPasswordHasher(bcrypt.DefaultCost)
	tokenSigner := services.NewTokenSigner()
	// TODO: Configure TokenSigner with keys from cfg (e.g. cfg.Config.SigningKeyPath)
	tokenSigner.AddKeySigner("temporary-secret-for-hs256-change-me")
	tokenCache := cache.NewMemoryTokenStore(1 * time.Minute)

	tokenService := services.NewTokenService(
		tokenRepo, // This is now conditional (DTS or Mongo)
		tokenCache,
		cfg.IssuerURL,
		tokenSigner,
		pubKeyRepo,
		saRepo,
		userRepo,
	)

	// The OIDCProviderService and its dependencies (like FlowStore, UserSessionStore)
	// would be initialized here. If DTS is used, dtsFlowStore and dtsUserSessionStore
	// (which were prepared earlier if DTS was selected) would be passed to it.
	// If MongoDB is used, InMemory stores would be used as per original SSSO.
	// Example:
	// var oidcService *services.OIDCService
	// if cfg.StorageBackend == string(alt_config.StorageTypeDTS) {
	//     oidcService = services.NewOIDCService(..., dtsFlowStore, dtsUserSessionStore, authCodeRepo, pkceRepo, ...)
	// } else {
	//     oidcService = services.NewOIDCService(..., oidcflow.NewInMemoryFlowStore(), oidcflow.NewInMemoryUserSessionStore(), authCodeRepo, pkceRepo, ...)
	// }
	// This part requires knowing the actual OIDC service constructor and its dependencies.
	// For now, we ensure the repositories are correctly chosen. The OIDC *stores* are also
	// conditionally prepared (dtsFlowStore, dtsUserSessionStore) for injection.

	log.Info().Msg("Core services (Token, User, SA, Auth) initialized with appropriate repositories.")
	if alt_config.StorageType(cfg.StorageBackend) == alt_config.StorageTypeDTS {
		if dtsFlowStore != nil && dtsUserSessionStore != nil {
			log.Info().Msg("DTS-backed OIDC flow and user session stores are ready for injection into an OIDC provider service.")
		}
	}


	// --- Initialize Interceptors ---
	authInterceptor := middleware.NewAuthInterceptor(tokenService)
	authzInterceptor := middleware.NewAuthorizationInterceptor()
	interceptors := connect.WithInterceptors(authInterceptor, authzInterceptor)

	// --- Initialize Service Handlers ---
	defaultKeyGen := &services.DefaultSAKeyGenerator{}
	saServer := services.NewServiceAccountServer(defaultKeyGen, saRepo, pubKeyRepo)
	userServer := services.NewUserServer(userRepo, passwordHasher)
	authServer := services.NewAuthServer(userRepo, sessionRepo, tokenService, passwordHasher)
	// oidcServer := services.NewOIDCServiceHandler(oidcProviderService, tokenService, ...) // Example for OIDC routes

	// --- Register handlers ---
	mux := http.NewServeMux()
	// Standard SSSO services
	saPath, saHandler := ssov1connect.NewServiceAccountServiceHandler(saServer, interceptors)
	mux.Handle(saPath, saHandler)
	userPath, userHandler := ssov1connect.NewUserServiceHandler(userServer, interceptors)
	mux.Handle(userPath, userHandler)
	authPath, authHandler := ssov1connect.NewAuthServiceHandler(authServer, interceptors)
	mux.Handle(authPath, authHandler)

	// OIDC specific handlers (e.g., .well-known, authorization, token, userinfo, jwks, etc.)
	// These would be registered by the oidcProviderService or a similar HTTP router setup.
	// Example:
	// if oidcProviderService != nil {
	// 	oidcProviderService.RegisterRoutes(mux) // Assuming it has a method to register its HTTP routes
	// }
	// Also, the existing Gin handlers in api/gin/ might need to be adapted or called by oidcProviderService.
	// For now, this setup focuses on the gRPC services. The full OIDC HTTP frontend is a larger scope.

	// Health checks
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
		// Readiness check might need to consider DTS client state if DTS is used.
		if alt_config.StorageType(cfg.StorageBackend) == alt_config.StorageTypeMongoDB ||
		   alt_config.StorageType(cfg.StorageBackend) == alt_config.StorageTypeDTS { // If DTS, still check Mongo for secondary
			if err := mongodb.Ping(ctx); err != nil {
				log.Error().Err(err).Msg("Readiness check failed: MongoDB ping failed")
				http.Error(w, "Service not ready: database connectivity issue", http.StatusServiceUnavailable)
				return
			}
		}
		// TODO: Add DTS health check if DTS is primary and critical for readiness.
		// e.g., dtsCli.DTS.Check(ctx, &grpc_health_v1.HealthCheckRequest{Service: "dts.v1.TokenStoreService"})
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	// --- Start HTTP/2 server ---
	srv := &http.Server{
		Addr:              cfg.HTTPAddr,
		Handler:           h2c.NewHandler(mux, &http2.Server{}),
		ReadHeaderTimeout: 3 * time.Second,
		ReadTimeout:       5 * time.Minute,
		WriteTimeout:      5 * time.Minute,
		MaxHeaderBytes:    8 * 1024,
	}
	log.Info().Msgf("SSSO-Alt ConnectRPC server (backend: %s) listening on %s", cfg.StorageBackend, cfg.HTTPAddr)
	return srv.ListenAndServe()
}
