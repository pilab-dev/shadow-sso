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

	// Pass the full application config to the server setup
	serverCfg := server.ServerConfig{
		AppConfig:          cfg, // cfg is the loaded application config
		PrometheusRegistry: promRegistry,
	}

	if err := server.Start(serverCfg); err != nil {
		log.Fatal().Err(err).Msg("Failed to start Shadow SSO server")
	}
}
