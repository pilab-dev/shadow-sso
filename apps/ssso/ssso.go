package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	ssso "github.com/pilab-dev/shadow-sso"
	"github.com/pilab-dev/shadow-sso/apps/ssso/config"
	"github.com/pilab-dev/shadow-sso/apps/ssso/server"
	"github.com/pilab-dev/shadow-sso/domain"
	"github.com/pilab-dev/shadow-sso/internal/metrics"
	"github.com/pilab-dev/shadow-sso/internal/telemetry"
	"github.com/pilab-dev/shadow-sso/mongodb"
	pkgauth "github.com/pilab-dev/shadow-sso/pkg/auth"
	"github.com/pilab-dev/shadow-sso/services"
	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/rs/zerolog/pkgerrors"
	"go.opentelemetry.io/contrib/instrumentation/github.com/gin-gonic/gin/otelgin"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
	"golang.org/x/crypto/bcrypt"
)

func requestIDMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		requestID := c.GetHeader("X-Request-ID")
		if requestID == "" {
			b := make([]byte, 16)
			_, _ = rand.Read(b)
			requestID = hex.EncodeToString(b)
		}

		c.Writer.Header().Set("X-Request-ID", requestID)
		c.Set("X-Request-ID", requestID)

		logger := zerolog.Ctx(c.Request.Context())
		if logger == nil {
			logger = &log.Logger
		}
		l := logger.With().Str("request_id", requestID).Logger()
		c.Request = c.Request.WithContext(l.WithContext(c.Request.Context()))

		c.Next()
	}
}

func corsMiddleware(allowedOrigins []string) gin.HandlerFunc {
	return func(c *gin.Context) {
		origin := c.GetHeader("Origin")

		if len(allowedOrigins) == 1 && allowedOrigins[0] == "*" {
			c.Header("Access-Control-Allow-Origin", "*")
		} else if origin != "" {
			for _, allowed := range allowedOrigins {
				if allowed == origin {
					c.Header("Access-Control-Allow-Origin", origin)
					c.Header("Access-Control-Allow-Credentials", "true")
					break
				}
			}
		}

		c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
		c.Header("Access-Control-Allow-Headers", "Origin, Content-Type, Accept, Authorization, X-Request-ID")

		if c.Request.Method == http.MethodOptions {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}

		c.Next()
	}
}

func main() {
	// Load .env file if it exists
	_ = godotenv.Load()

	cfg, err := config.LoadConfig()
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to load configuration")
	}

	// Configure logger: JSON for production (Loki), pretty console for local dev
	if cfg.JSONLog {
		log.Logger = zerolog.New(os.Stdout).With().Timestamp().Logger()
	} else {
		consoleWriter := zerolog.ConsoleWriter{Out: os.Stdout}
		log.Logger = zerolog.New(consoleWriter).With().Timestamp().Logger()
	}
	zerolog.ErrorStackMarshaler = pkgerrors.MarshalStack

	// Set log level
	logLevel, err := zerolog.ParseLevel(cfg.LogLevel)
	if err != nil {
		log.Warn().Str("configured_level", cfg.LogLevel).Msg("Invalid log level in config, defaulting to info")
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	} else {
		zerolog.SetGlobalLevel(logLevel)
	}

	log.Info().Msg(fmt.Sprintf("Shadow SSO server starting on %s", cfg.HTTPAddr))

	// Initialize OpenTelemetry
	otel.SetTextMapPropagator(
		propagation.NewCompositeTextMapPropagator(
			propagation.TraceContext{},
			propagation.Baggage{},
		),
	)
	if cfg.TracingEnabled {
		tracerProvider, err := telemetry.InitTracer(context.Background(), "shadow-sso")
		if err != nil {
			log.Warn().Err(err).Msg("Failed to initialize tracing, continuing without it")
		} else {
			defer telemetry.Shutdown(context.Background(), tracerProvider, nil)
		}
	} else {
		log.Info().Msg("Tracing disabled — skip InitTracer (set SSSO_TRACING_ENABLED=true to enable)")
	}

	// Create a new Prometheus registry
	promRegistry := prometheus.NewRegistry()
	// Register standard Go collectors
	promRegistry.MustRegister(prometheus.NewGoCollector())
	promRegistry.MustRegister(prometheus.NewProcessCollector(prometheus.ProcessCollectorOpts{}))

	// Initialize and register custom metrics
	metrics.InitCustomMetrics(promRegistry)

	meterProvider, err := telemetry.InitMeterProvider(promRegistry)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to initialize OpenTelemetry MeterProvider")
	}
	defer telemetry.Shutdown(context.Background(), nil, meterProvider) // Shutdown meter on exit

	// Initialize RepositoryProvider based on StorageBackend
	var repoProvider services.RepositoryProvider
	if cfg.StorageBackend == config.StorageTypeDTS {
		log.Fatal().Msg("DTS storage backend is not yet fully integrated with the public API. Please use MongoDB for now.")
	} else {
		log.Info().Msg("Initializing MongoDB repository provider.")
		repoProvider, err = ssso.NewMongoRepositoryProvider(cfg.MongoURI, cfg.MongoDBName)
		if err != nil {
			log.Fatal().Err(err).Msg("Failed to initialize MongoDB repository provider")
		}
		// Ensure MongoDB client is disconnected on exit
		if mongoRp, ok := repoProvider.(*mongodb.MongoRepositoryProvider); ok {
			defer func() { _ = mongoRp.Disconnect(context.Background()) }()
		}
	}

	// Bootstrap default configurations from environment variables
	log.Info().Msg("Bootstrapping default configurations...")
	configRepo := repoProvider.ConfigurationRepository(context.Background())
	if err := configRepo.CreateDefaultConfigs(context.Background()); err != nil {
		log.Warn().Err(err).Msg("Failed to bootstrap default configurations, some features may not work correctly")
	} else {
		log.Info().Msg("Default configurations bootstrapped successfully")
	}

	// Bootstrap initial admin user and client from environment variables
	if cfg.InitialAdminEnabled && cfg.InitialAdminEmail != "" && cfg.InitialAdminPassword != "" {
		bCtx := context.Background()

		// Create admin user if not exists
		userRepo := repoProvider.UserRepository(bCtx)
		_, uErr := userRepo.GetUserByEmail(bCtx, cfg.InitialAdminEmail)
		if errors.Is(uErr, domain.ErrUserNotFound) {
			passwordHasher := pkgauth.NewBcryptPasswordHasher(bcrypt.DefaultCost)
			hash, pHashErr := passwordHasher.Hash(cfg.InitialAdminPassword)
			if pHashErr != nil {
				log.Warn().Err(pHashErr).Msg("Failed to hash initial admin password, skipping user creation")
			} else {
				user := &domain.User{
					Email:        cfg.InitialAdminEmail,
					PasswordHash: hash,
					FirstName:    cfg.InitialAdminFirstName,
					LastName:     cfg.InitialAdminLastName,
					Status:       domain.UserStatusActive,
				}
				if createErr := userRepo.CreateUser(bCtx, user); createErr != nil {
					log.Warn().Err(createErr).Str("email", cfg.InitialAdminEmail).Msg("Failed to create initial admin user")
				} else {
					log.Info().Str("email", cfg.InitialAdminEmail).Msg("Initial admin user created")
				}
			}
		} else if uErr != nil {
			log.Warn().Err(uErr).Msg("Failed to check for existing admin user")
		} else {
			log.Info().Str("email", cfg.InitialAdminEmail).Msg("Initial admin user already exists, skipping creation")
		}

		// Create or update confidential admin-ui client
		clientRepo := repoProvider.ClientRepository(bCtx)
		existingClient, cErr := clientRepo.GetClient(bCtx, "admin-ui")
		if cErr != nil {
			// Client does not exist — create it
			clientSecret := cfg.InitialAdminClientSecret
			autoGenerated := false
			if clientSecret == "" {
				clientSecret = mongodb.NewID()
				autoGenerated = true
			}
			// Hash the secret so ValidateClient (bcrypt compare) works
			hashedSecret, hashErr := bcrypt.GenerateFromPassword([]byte(clientSecret), bcrypt.DefaultCost)
			if hashErr != nil {
				log.Warn().Err(hashErr).Msg("Failed to hash admin-ui client secret, skipping client creation")
			} else {
				client := &domain.Client{
					ID:                "admin-ui",
					Secret:            string(hashedSecret),
					Type:              domain.ClientTypeConfidential,
					Name:              "Admin UI",
					AllowedGrantTypes: []string{"password", "refresh_token", "client_credentials"},
					AllowedScopes:     []string{"openid", "profile", "email"},
					IsActive:          true,
					IsConfidential:    true,
					TokenEndpointAuth: "client_secret_post",
					ServiceAccountRoles: []string{"ROLE_ADMIN"},
				}
				if createErr := clientRepo.CreateClient(bCtx, client); createErr != nil {
					log.Warn().Err(createErr).Msg("Failed to create admin-ui client")
				} else {
					log.Warn().Str("client_id", "admin-ui").Str("client_secret", clientSecret).
						Bool("auto_generated", autoGenerated).
						Msg("Admin UI OAuth client created - SAVE client_secret for login")
				}
			}
		} else {
			// Client exists — ensure it has client_credentials grant and admin roles
			needsUpdate := false
			hasCC := false
			for _, gt := range existingClient.AllowedGrantTypes {
				if gt == "client_credentials" {
					hasCC = true
					break
				}
			}
			if !hasCC {
				existingClient.AllowedGrantTypes = append(existingClient.AllowedGrantTypes, "client_credentials")
				needsUpdate = true
			}
			if len(existingClient.ServiceAccountRoles) == 0 {
				existingClient.ServiceAccountRoles = []string{"ROLE_ADMIN"}
				needsUpdate = true
			}
			// Also note if secret is not bcrypt-hashed (migration from plaintext)
			if !strings.HasPrefix(existingClient.Secret, "$2a$") &&
				!strings.HasPrefix(existingClient.Secret, "$2b$") &&
				existingClient.Secret != "" {
				log.Warn().Msg("admin-ui client secret is not bcrypt-hashed, this will break authentication. " +
					"Regenerate the secret via GraphQL GenerateClientSecret mutation.")
				needsUpdate = true
			}
			if needsUpdate {
				if updateErr := clientRepo.UpdateClient(bCtx, existingClient); updateErr != nil {
					log.Warn().Err(updateErr).Msg("Failed to update admin-ui client")
				} else {
					log.Info().Msg("Admin UI client updated with client_credentials grant type")
				}
			} else {
				log.Info().Msg("Admin UI client already exists and is up-to-date")
			}
		}
	}

	// Start SSO server
	mainSrv, err := server.StartServer(cfg, repoProvider,
		server.WithExtraMiddlewares(
			corsMiddleware(cfg.AllowedOrigins),
			requestIDMiddleware(),
			otelgin.Middleware("shadow-sso"),
		),
	)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to start SSO server")
	}

	// Start management server on a separate port for health, metrics, pprof
	mgmtSrv := server.StartManagementServer(cfg.MgmtHTTPAddr, repoProvider, promRegistry)
	log.Info().Str("addr", cfg.MgmtHTTPAddr).Msg("Management server started")

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	sig := <-quit
	log.Info().Str("signal", sig.String()).Msg("Initiating graceful shutdown...")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := mainSrv.Shutdown(ctx); err != nil {
		log.Error().Err(err).Msg("Main server forced to shutdown")
	} else {
		log.Info().Msg("Main server shut down successfully")
	}

	if err := mgmtSrv.Shutdown(ctx); err != nil {
		log.Error().Err(err).Msg("Management server forced to shutdown")
	} else {
		log.Info().Msg("Management server shut down successfully")
	}
}
