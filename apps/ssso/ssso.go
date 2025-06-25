package main

import (
	"fmt"
	// "os" // No longer needed for direct env var reading here

	"github.com/pilab-dev/shadow-sso/internal/server" // Adjusted import path
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


	serverCfg := server.ServerConfig{
		HTTPAddr:    cfg.HTTPAddr,
		MongoURI:    cfg.MongoURI,
		MongoDBName: cfg.MongoDBName,
		IssuerURL:   cfg.IssuerURL,
		// SigningKeyPath: cfg.SigningKeyPath, // Pass these when server is ready to use them
		// KeyRotationInterval: cfg.KeyRotationInterval,
		// NextJSLoginURL: cfg.NextJSLoginURL,
	}

	if err := server.StartConnectRPCServer(serverCfg); err != nil {
		log.Fatal().Err(err).Msg("Failed to start Shadow SSO server")
	}
}
