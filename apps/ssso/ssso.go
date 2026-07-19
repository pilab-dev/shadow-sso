package main

import (
	"context"
	"errors"
	"fmt"
	"os"

	ssso "github.com/pilab-dev/shadow-sso"
	"github.com/pilab-dev/shadow-sso/apps/ssso/config"
	"github.com/pilab-dev/shadow-sso/cache"
	"github.com/pilab-dev/shadow-sso/domain"
	"github.com/pilab-dev/shadow-sso/internal/metrics"
	"github.com/pilab-dev/shadow-sso/internal/telemetry"
	"github.com/pilab-dev/shadow-sso/mongodb"
	pkgauth "github.com/pilab-dev/shadow-sso/pkg/auth"
	"github.com/pilab-dev/shadow-sso/services"
	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/rs/zerolog/pkgerrors"
	"golang.org/x/crypto/bcrypt"
)

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
	tracerProvider, err := telemetry.InitTracer()
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to initialize OpenTelemetry TracerProvider")
	}
	defer telemetry.Shutdown(context.Background(), tracerProvider, nil) // Shutdown tracer on exit

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

	// Map internal config to public api.OpenIDProviderConfig
	oidcConfig := cfg.ToOpenIDProviderConfig()

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
			defer mongoRp.Disconnect(context.Background())
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

		// Create confidential admin-ui client if not exists
		clientRepo := repoProvider.ClientRepository(bCtx)
		_, cErr := clientRepo.GetClient(bCtx, "admin-ui")
		if cErr != nil {
			clientSecret := cfg.InitialAdminClientSecret
			autoGenerated := false
			if clientSecret == "" {
				clientSecret = mongodb.NewID()
				autoGenerated = true
			}
			client := &domain.Client{
				ID:                "admin-ui",
				Secret:            clientSecret,
				Type:              domain.ClientTypeConfidential,
				Name:              "Admin UI",
				AllowedGrantTypes: []string{"password", "refresh_token"},
				AllowedScopes:     []string{"openid", "profile", "email"},
				IsActive:          true,
				IsConfidential:    true,
				TokenEndpointAuth: "client_secret_post",
			}
			if createErr := clientRepo.CreateClient(bCtx, client); createErr != nil {
				log.Warn().Err(createErr).Msg("Failed to create admin-ui client")
			} else {
				log.Warn().Str("client_id", "admin-ui").Str("client_secret", clientSecret).
					Bool("auto_generated", autoGenerated).
					Msg("Admin UI OAuth client created - SAVE client_secret for login")
			}
		} else {
			log.Info().Msg("Admin UI client already exists, skipping creation")
		}
	}

	// Initialize TokenSigner (potentially from file/env)
	tokenSigner := services.NewTokenSigner()
	if cfg.SigningKeyPath != "" {
		if err := tokenSigner.AddRSASigner(cfg.SigningKeyPath); err != nil {
			log.Warn().Err(err).Str("path", cfg.SigningKeyPath).Msg("Failed to load RSA signing key, falling back to HS256")
			tokenSigner.AddKeySigner("temporary-secret-for-hs256-change-me")
		} else {
			log.Info().Msg("RSA signing key loaded successfully (RS256)")
		}
	} else if cfg.TokenSigningKey != "" {
		tokenSigner.AddKeySigner(cfg.TokenSigningKey)
		log.Info().Msg("Token signing key loaded from config (HS256).")
	} else {
		log.Warn().Msg("No token signing key configured. Using placeholder - REPLACE IN PRODUCTION.")
		tokenSigner.AddKeySigner("temporary-secret-for-hs256-change-me")
	}

	// Get encryption key for configuration service from viper config
	encryptionKey := cfg.ConfigEncryptionKey

	// Create SSOServerOptions
	opts := ssso.SSOServerOptions{
		Config:             oidcConfig,
		AppConfig:          &cfg,
		RepositoryProvider: repoProvider,
		TokenSigner:        tokenSigner,
		TokenCache:         cache.NewMemoryTokenStore(oidcConfig.AccessTokenTTL), // Use OIDC config's TTL
		PkceRepository:     nil, // Let NewSSOServer default to in-memory if not provided by repoProvider
		FlowStore:          nil, // Let NewSSOServer default to in-memory
		UserSessionStore:   nil, // Let NewSSOServer default to in-memory
		EncryptionKey:      encryptionKey,
	}

	router, err := ssso.NewSSOServer(opts)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to initialize SSO server")
	}

	// Add Prometheus metrics handler to the router.
	// This is done after NewSSOServer to ensure that any handlers registered by NewSSOServer are not overwritten.
	router.GET("/metrics", gin.WrapH(promhttp.HandlerFor(promRegistry, promhttp.HandlerOpts{EnableOpenMetrics: true})))
	log.Info().Msg("Prometheus metrics endpoint enabled at /metrics")

	log.Info().Msgf("SSO server ready to listen on %s", cfg.HTTPAddr)
	if err := router.Run(cfg.HTTPAddr); err != nil {
		log.Fatal().Err(err).Msg("Failed to start SSO server")
	}
}
