package main

import (
	"fmt"
	"os"
	"time"

	alt_config "github.com/pilab-dev/ssso/apps/ssso-alt/config" // Local alt config
	// Local alt server (to be created)
	alt_server "github.com/pilab-dev/ssso/apps/ssso-alt/internal/server"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

func main() {
	// Load ssso-alt specific configuration
	cfg := alt_config.LoadConfig()

	// Set log level from the base config part
	logLevel, err := zerolog.ParseLevel(cfg.Config.LogLevel)
	if err != nil {
		log.Warn().Str("configured_level", cfg.Config.LogLevel).Msg("Invalid log level in config, defaulting to info")
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	} else {
		zerolog.SetGlobalLevel(logLevel)
	}

	log.Info().Msg(fmt.Sprintf("Shadow SSO (ALT VERSION with %s backend) server starting on %s", cfg.StorageBackend, cfg.Config.HTTPAddr))
	// Redact sensitive parts of config before logging if necessary
	// log.Info().Interface("configuration", cfg).Msg("Loaded SSSO-ALT configuration")


	// Prepare server configuration for the alt server startup function
	// This will now pass the full alt_config.Config
	serverCfg := alt_server.ServerConfig{
		HTTPAddr:    cfg.Config.HTTPAddr,
		MongoURI:    cfg.Config.MongoURI,    // Needed if MongoDB is selected or for mixed mode
		MongoDBName: cfg.Config.MongoDBName,  // Needed if MongoDB is selected
		IssuerURL:   cfg.Config.IssuerURL,
		// DTS specific fields for the new ServerConfig struct in alt_server
		StorageBackend:    string(cfg.StorageBackend),
		DTSClientAddress:  cfg.DTSClientAddress,
		DTSConnectTimeout: cfg.DTSConnectTimeout,
		DTSDefaultPKCETTL: cfg.DTSDefaultPKCETTL,
		// Pass other relevant fields from cfg.Config as needed by services
		// Example: cfg.Config.SigningKeyPath, etc.
	}


	if err := alt_server.StartConnectRPCServer(serverCfg); err != nil {
		log.Fatal().Err(err).Msg("Failed to start Shadow SSO (ALT VERSION) server")
	}
}

func init() {
	// Ensure logs are initialized (zerolog default is fine but can be customized here)
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: time.RFC3339})
	zerolog.SetGlobalLevel(zerolog.InfoLevel) // Default, overridden by config later
}
