package main

import (
	"context"
	"fmt"

	ssso "github.com/pilab-dev/shadow-sso"
	"github.com/pilab-dev/shadow-sso/apps/ssso/config"
	"github.com/pilab-dev/shadow-sso/cache"
	"github.com/pilab-dev/shadow-sso/internal/metrics"
	"github.com/pilab-dev/shadow-sso/internal/telemetry"
	"github.com/pilab-dev/shadow-sso/mongodb"
	"github.com/pilab-dev/shadow-sso/services"
	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rs/zerolog"
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

	// Initialize TokenSigner (potentially from file/env)
	tokenSigner := services.NewTokenSigner()
	if cfg.TokenSigningKey != "" {
		tokenSigner.AddKeySigner(cfg.TokenSigningKey)
		log.Info().Msg("Token signing key loaded from config (plaintext).")
	} else if cfg.TokenSigningKeyFile != "" {
		// TODO: Implement robust RSA key loading from PEM file.
		// For production, this should load a proper RSA private key for RS256/384/512.
		log.Warn().Msgf("Token signing key file '%s' specified, but robust loading for RSA not implemented. Using placeholder.", cfg.TokenSigningKeyFile)
		tokenSigner.AddKeySigner("temporary-secret-from-file-placeholder") // Fallback for HS256
	} else {
		log.Warn().Msg("No token signing key configured. Using placeholder - REPLACE IN PRODUCTION.")
		tokenSigner.AddKeySigner("temporary-secret-for-hs256-change-me") // Fallback for HS256
	}

	// Create SSOServerOptions
	opts := ssso.SSOServerOptions{
		Config:             oidcConfig,
		RepositoryProvider: repoProvider,
		TokenSigner:        tokenSigner,
		TokenCache:         cache.NewMemoryTokenStore(oidcConfig.AccessTokenTTL), // Use OIDC config's TTL
		PkceRepository:     nil, // Let NewSSOServer default to in-memory if not provided by repoProvider
		FlowStore:          nil, // Let NewSSOServer default to in-memory
		UserSessionStore:   nil, // Let NewSSOServer default to in-memory
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
