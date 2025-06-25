package main

import (
	"context"
	"fmt"
	"net" // Added for net.Listen
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"google.golang.org/grpc" // Added for grpc.Server

	"github.com/pilab-dev/shadow-sso/config"
	"github.com/pilab-dev/shadow-sso/log"
	"github.com/pilab-dev/shadow-sso/tracing"

	ssso "github.com/pilab-dev/shadow-sso"
	ginapi "github.com/pilab-dev/shadow-sso/api/gin"
	"github.com/pilab-dev/shadow-sso/cache"
	"github.com/pilab-dev/shadow-sso/client"
	"github.com/pilab-dev/shadow-sso/internal/auth"
	"github.com/pilab-dev/shadow-sso/internal/server"
	"github.com/pilab-dev/shadow-sso/mongodb"
	"github.com/pilab-dev/shadow-sso/services"
	"github.com/rs/zerolog"
	sdktrace "go.opentelemetry.io/otel/sdk/trace" // For concrete TracerProvider type
	"golang.org/x/crypto/bcrypt"
)

var (
	appLogger      log.Logger
	httpServer     *http.Server
	grpcServer     *grpc.Server
	tracerProvider *sdktrace.TracerProvider // Use concrete type for shutdown
)

func main() {
	// Load configuration first
	cfg, err := config.LoadConfig()
	if err != nil {
		stdLog := zerolog.New(os.Stdout).With().Timestamp().Logger()
		stdLog.Fatal().Err(err).Msg("Failed to load configuration")
	}

	// Initialize Logger
	logLevel, parseErr := zerolog.ParseLevel(cfg.LogLevel)
	if parseErr != nil {
		logLevel = zerolog.InfoLevel
		zerolog.New(os.Stdout).With().Timestamp().Logger().Warn().
			Str("configured_log_level", cfg.LogLevel).
			Str("fallback_log_level", logLevel.String()).
			Err(parseErr).
			Msg("Invalid LOG_LEVEL configured, defaulting to 'info'")
	}
	appLogger = log.NewZerologAdapter(logLevel, cfg.LogPretty)
	appLogger.Info(context.Background(), "Logger initialized.")
	appLogger.Info(context.Background(), "Starting shadow-sso server...")
	appLogger.Info(context.Background(), "Configuration loaded successfully", map[string]interface{}{
		"http_port":     cfg.HTTPPort,
		"grpc_port":     cfg.GRPCPort,
		"mongo_uri":     cfg.MongoURI,
		"mongo_db_name": cfg.MongoDBName,
		"log_level":     cfg.LogLevel,
		"log_pretty":    cfg.LogPretty,
		"otel_service":  cfg.OtelServiceName,
	})

	// Initialize OpenTelemetry TracerProvider
	tp, err := tracing.InitTracerProvider(cfg.OtelServiceName) // tp is *sdktrace.TracerProvider
	if err != nil {
		appLogger.Fatal(context.Background(), "Failed to initialize TracerProvider", err, nil)
	}
	tracerProvider = tp // Assign to global var for deferred shutdown
	appLogger.Info(context.Background(), "TracerProvider initialized.")

	// --- Initialize Dependencies ---
	ctx := context.Background()
	if initErr := mongodb.InitMongoDB(ctx, cfg.MongoURI, cfg.MongoDBName); initErr != nil {
		appLogger.Fatal(ctx, "Failed to initialize MongoDB connection", initErr, nil)
	}
	db := mongodb.GetDB()

	// Repositories
	oauthRepo, err := mongodb.NewOAuthRepository(ctx, db)
	if err != nil {
		appLogger.Fatal(ctx, "Failed to initialize OAuthRepository", err, nil)
	}

	userRepo, err := mongodb.NewUserRepository(ctx, db)
	if err != nil {
		appLogger.Fatal(ctx, "Failed to initialize UserRepository", err, nil)
	}

	idpRepo, err := mongodb.NewIdPRepositoryMongo(ctx, db)
	if err != nil {
		appLogger.Fatal(ctx, "Failed to initialize IdPRepository", err, nil)
	}

	sessionRepo, err := mongodb.NewSessionRepositoryMongo(ctx, db)
	if err != nil {
		appLogger.Fatal(ctx, "Failed to initialize SessionRepository", err, nil)
	}

	pubKeyRepo, err := mongodb.NewPublicKeyRepositoryMongo(db)
	if err != nil {
		appLogger.Fatal(ctx, "Failed to initialize PublicKeyRepository", err, nil)
	}

	saRepo, err := mongodb.NewServiceAccountRepositoryMongo(db)
	if err != nil {
		appLogger.Fatal(ctx, "Failed to initialize ServiceAccountRepository", err, nil)
	}

	// Services
	passwordHasher := auth.NewBcryptPasswordHasher(bcrypt.DefaultCost)

	tokenRepoAssertion, ok := oauthRepo.(ssso.TokenRepository)
	if !ok {
		appLogger.Fatal(ctx, "mongodb.OAuthRepository does not implement ssso.TokenRepository", nil, nil)
	}
	tokenSigner := ssso.NewTokenSigner() // TODO: Configure keys
	tokenCache := cache.NewMemoryTokenStore(1 * time.Minute)
	tokenService := ssso.NewTokenService(tokenRepoAssertion, tokenCache, cfg.OtelServiceName /*TODO: Issuer URL*/, tokenSigner, pubKeyRepo, saRepo, userRepo)

	userServiceInternal := services.NewUserService(userRepo, passwordHasher)
	idpServiceInternal := services.NewIdPService(idpRepo)
	clientServiceInternal := services.NewClientServiceImpl(oauthRepo, passwordHasher) // OAuthRepo implements ClientStore via embedding

	// HTTP API (Gin) Dependencies
	oauthSvc := ssso.NewOAuthService(oauthRepo, userServiceInternal, tokenService, cfg.OtelServiceName /*TODO: Issuer URL*/, appLogger)
	jwksService := ssso.NewJWKSService(tokenSigner) // TODO: Configure
	clientStoreAssertion, ok := oauthRepo.(client.ClientStore)
	if !ok {
		appLogger.Fatal(ctx, "mongodb.OAuthRepository does not implement client.ClientStore", nil, nil)
	}
	clientSvc := client.NewClientService(clientStoreAssertion)
	pkceRepoAssertion, ok := oauthRepo.(ssso.PkceRepository)
	if !ok {
		appLogger.Fatal(ctx, "mongodb.OAuthRepository does not implement ssso.PkceRepository", nil, nil)
	}
	pkceService := ssso.NewPKCEService(pkceRepoAssertion)
	oidcCfg := ssso.NewDefaultConfig(cfg.OtelServiceName /*TODO: Issuer URL*/)
	oauthAPI := ginapi.NewOAuth2API(oauthSvc, jwksService, clientSvc, pkceService, oidcCfg)

	// gRPC/ConnectRPC Service Handlers
	authRPCHandler := services.NewAuthServer(userRepo, sessionRepo, tokenService, passwordHasher)
	idpRPCHandler := services.NewIdPManagementServer(idpServiceInternal)
	userRPCHandler := services.NewUserServer(userServiceInternal)
	clientRPCHandler := services.NewClientManagementServer(clientServiceInternal)
	defaultKeyGen := &services.DefaultSAKeyGenerator{}
	saRPCHandler := services.NewServiceAccountServer(defaultKeyGen, saRepo, pubKeyRepo)
	twoFactorRPCHandler := services.NewTwoFactorServer(userRepo, passwordHasher, "ShadowSSO" /*TODO: App Name from Config*/)

	// --- End Dependency Initialization ---

	// Setup and Start Gin HTTP Server
	httpServer = server.NewHTTPServer(cfg, appLogger, oauthAPI)
	go func() {
		appLogger.Info(context.Background(), fmt.Sprintf("HTTP server listening on port %s", cfg.HTTPPort))
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			appLogger.Fatal(context.Background(), "Failed to start HTTP server", err, nil)
		}
	}()

	// Setup and Start gRPC Server
	// Pass the RPC Handlers. NewGRPCServer needs to be adapted to accept these.
	// For now, demonstrating with one handler.
	// The NewGRPCServer function needs to be updated to actually register these.
	grpcServer = server.NewGRPCServer(cfg, appLogger) // idpRPCHandler, // Example: This would require NewGRPCServer to accept ssov1connect.IdPManagementServiceHandler
	// userRPCHandler,
	// clientRPCHandler,
	// authRPCHandler,
	// twoFactorRPCHandler,
	// saRPCHandler,

	go func() {
		grpcPort := cfg.GRPCPort
		if grpcPort == "" {
			grpcPort = "8081" // Default from LoadConfig if not overridden
		}
		lis, err := net.Listen("tcp", ":"+grpcPort)
		if err != nil {
			appLogger.Fatal(context.Background(), fmt.Sprintf("Failed to listen on gRPC port %s", grpcPort), err, nil)
		}
		appLogger.Info(context.Background(), fmt.Sprintf("gRPC server listening on port %s", grpcPort))
		if err := grpcServer.Serve(lis); err != nil && err != grpc.ErrServerStopped {
			appLogger.Fatal(context.Background(), "Failed to start gRPC server", err, nil)
		}
	}()

	// Note: The existing ConnectRPC server setup in internal/server/connectrpc_server.go
	// also starts an HTTP server. If both are run, they need distinct ports or one setup needs to be chosen/merged.
	// The DI here prepares dependencies for both. The commented-out StartConnectRPCServer call
	// from the previous version of main.go is omitted here to avoid port conflicts if GRPCPort and HTTPPort are the same.
	// If ConnectRPC services are to be hosted on the `grpcServer` instance, `internal/server/grpc_server.go`
	// would need to change how it registers services (Connect handlers are http.Handler, not direct gRPC service impls).

	appLogger.Info(context.Background(), "Server components initialized. Waiting for interrupt signal...")

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	receivedSignal := <-quit

	appLogger.Info(context.Background(), fmt.Sprintf("Received signal: %v. Shutting down server...", receivedSignal))

	shutdownCtx, cancelShutdown := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancelShutdown()

	if httpServer != nil {
		appLogger.Info(shutdownCtx, "Shutting down HTTP server...")
		if err := httpServer.Shutdown(shutdownCtx); err != nil {
			appLogger.Error(shutdownCtx, "HTTP server shutdown error", err, nil)
		}
	}

	if grpcServer != nil {
		appLogger.Info(shutdownCtx, "Shutting down gRPC server...")
		grpcServer.GracefulStop()
	}

	if tracerProvider != nil {
		appLogger.Info(shutdownCtx, "Shutting down TracerProvider...")
		if err := tracerProvider.Shutdown(shutdownCtx); err != nil {
			appLogger.Error(shutdownCtx, "TracerProvider shutdown error", err, nil)
		}
	}

	appLogger.Info(shutdownCtx, "Closing MongoDB connection...")
	mongodb.CloseMongoDB(shutdownCtx)

	appLogger.Info(shutdownCtx, "Server gracefully stopped.")
}
