package main

import (
	"context"
	"fmt"

	// "os" // No longer needed for direct env var reading here

	"github.com/pilab-dev/shadow-sso/apps/ssso/config"
	"github.com/pilab-dev/shadow-sso/apps/ssso/server"
	"github.com/pilab-dev/shadow-sso/internal/metrics" // Import for custom metrics
	"github.com/pilab-dev/shadow-sso/internal/telemetry"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/rs/zerolog" // For setting log level
	"github.com/rs/zerolog/log"
)

func main() {
	cfg, err := config.LoadConfig()
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to load configuration")
	}

	// Set log level
	logLevel, err := zerolog.ParseLevel(cfg.LogLevel)
	if err != nil {
		log.Warn().Str("configured_level", cfg.LogLevel).Msg("Invalid log level in config, defaulting to info")
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	} else {
		zerolog.SetGlobalLevel(logLevel)
	}

	log.Info().Msg(fmt.Sprintf("Shadow SSO server starting on %s", cfg.HTTPAddr))
	log.Info().Interface("configuration", cfg).Msg("Loaded configuration")

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

	// Initialize RepositoryProvider
	repoProvider, err := mongodb.NewMongoRepositoryProvider(cfg.MongoURI, cfg.MongoDBName)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to initialize MongoRepositoryProvider")
	}
	defer repoProvider.Disconnect(context.Background()) // Ensure disconnection
	log.Info().Msg("MongoRepositoryProvider initialized.")

	// Initialize TokenSigner
	tokenSigner := services.NewTokenSigner()
	if cfg.TokenSigningKey != "" { // Assuming cfg.TokenSigningKey holds the primary key material or path
		// TODO: Implement robust key loading logic from configuration (e.g., type, path, actual key)
		// For now, using it directly if it's simple, or placeholder.
		log.Info().Str("key_source", "config (simplified)").Msg("Loading token signing key.")
		tokenSigner.AddKeySigner(cfg.TokenSigningKey) // This is a simplified assumption
	} else if cfg.TokenSigningKeyFile != "" {
		log.Info().Str("key_file", cfg.TokenSigningKeyFile).Msg("Loading token signing key from file.")
		// TODO: Add logic to read key from cfg.TokenSigningKeyFile
		// For now, placeholder if file logic not implemented:
		log.Warn().Msg("Token signing key file loading not implemented, using placeholder.")
		tokenSigner.AddKeySigner("temporary-secret-for-hs256-change-me")
	} else {
		log.Warn().Msg("No token signing key configured, using placeholder - REPLACE IN PRODUCTION")
		tokenSigner.AddKeySigner("temporary-secret-for-hs256-change-me")
	}

	// Initialize TokenCache
	var tokenCache cache.TokenStore
	if cfg.CacheBackend == "redis" && cfg.RedisAddress != "" {
		log.Info().Str("address", cfg.RedisAddress).Msg("Initializing Redis token cache.")
		tokenCache = cache.NewRedisTokenStore(&cache.RedisConfig{
			Address:  cfg.RedisAddress,
			Password: cfg.RedisPassword, // Ensure this field exists in appconfig.Config
			DB:       cfg.RedisDB,       // Ensure this field exists in appconfig.Config
		})
	} else {
		log.Info().Msg("Initializing in-memory token cache.")
		tokenCache = cache.NewMemoryTokenStore(cfg.TokenCacheDefaultTTL)
	}

	// Initialize PkceRepository
	var pkceRepo domain.PkceRepository
	if cfg.StorageBackend == config.StorageTypeDTS {
		log.Info().Msg("Initializing DTS client for PKCE repository.")
		dtsAPIClient, dtsErr := dtsclient.NewClient(dtsclient.Config{
			Address:        cfg.DTSClientAddress,
			ConnectTimeout: cfg.DTSConnectTimeout,
		})
		if dtsErr != nil {
			log.Fatal().Err(dtsErr).Msg("Failed to create DTS API Client for PKCE")
		}
		pkceRepo = dtsclient.NewDTSPkceRepository(dtsAPIClient, cfg.DTSDefaultPKCETTL)
		log.Info().Msg("DTS PKCE Repository initialized.")
	} else {
		// If not DTS, try to get from MongoRepositoryProvider.
		// This relies on MongoRepositoryProvider.PkceRepository() returning a valid implementation.
		// (Currently, it attempts a type assertion on the auth code repo).
		pkceRepo = repoProvider.PkceRepository(context.Background())
		if pkceRepo == nil {
			// This will happen if mongoAuthCodeRepository doesn't implement PkceRepository.
			// For a production system, this should be a fatal error or a clear fallback.
			// As per current MongoRepositoryProvider, it returns nil if type assertion fails.
			log.Fatal().Msg("Failed to initialize PKCE repository: MongoDB provider did not supply one, and not using DTS.")
			// To allow startup for now IF PKCE is not strictly needed immediately or for all flows,
			// one might use an in-memory stub, but this is not ideal.
			// pkceRepo = oidcflow.NewInMemoryPKCERepository() // Example of a temporary in-memory one
			// log.Warn().Msg("Initialized in-memory PKCE repository as a fallback.")
		} else {
			log.Info().Msg("MongoDB PKCE Repository (via AuthCodeRepository) initialized.")
		}
	}


	// Initialize ServiceProvider
	log.Info().Msg("Initializing ServiceProvider...")
	serviceProviderOpts := services.DefaultServiceProviderOptions{
		RepositoryProvider: repoProvider,
		Config:             &cfg,
		TokenSigner:        tokenSigner,
		TokenCache:         tokenCache,
		PkceRepository:     pkceRepo, // Pass the explicitly created PkceRepository
		// FlowStore and UserSessionStore will be initialized by DefaultServiceProvider if nil
	}
	serviceProvider, err := services.NewDefaultServiceProvider(serviceProviderOpts)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to initialize DefaultServiceProvider")
	}
	log.Info().Msg("ServiceProvider initialized.")

	// Pass the ServiceProvider and other necessary parts of cfg to the server setup
	serverCfg := server.ServerConfig{
		AppConfig:          cfg, // Still pass AppConfig for httpAddr, Prometheus, etc.
		PrometheusRegistry: promRegistry,
		ServiceProvider:    serviceProvider, // Pass the initialized ServiceProvider
	}

	if err := server.Start(serverCfg); err != nil {
		log.Fatal().Err(err).Msg("Failed to start Shadow SSO server")
	}
}
