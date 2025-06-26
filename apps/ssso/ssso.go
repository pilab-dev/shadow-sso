package main

import (
	"context"
	"fmt"
	// "os" // No longer needed for direct env var reading here

	"github.com/pilab-dev/shadow-sso/internal/metrics" // Import for custom metrics
	"github.com/pilab-dev/shadow-sso/internal/server" // Adjusted import path
	"github.com/pilab-dev/shadow-sso/internal/telemetry"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/rs/zerolog/log"
	"github.com/rs/zerolog" // For setting log level
)

func main() {
	cfg, err := LoadConfig()
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


	serverCfg := server.ServerConfig{
		HTTPAddr:          cfg.HTTPAddr,
		MongoURI:          cfg.MongoURI,
		MongoDBName:       cfg.MongoDBName,
		IssuerURL:         cfg.IssuerURL,
		PrometheusRegistry: promRegistry,
		// SigningKeyPath: cfg.SigningKeyPath, // Pass these when server is ready to use them
		// KeyRotationInterval: cfg.KeyRotationInterval,
		// NextJSLoginURL: cfg.NextJSLoginURL,
	}

	if err := server.StartConnectRPCServer(serverCfg); err != nil {
		log.Fatal().Err(err).Msg("Failed to start Shadow SSO server")
	}
}
