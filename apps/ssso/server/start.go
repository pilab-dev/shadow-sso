package server

import (
	"fmt"
	"net"
	"net/http"

	"context"

	ssso "github.com/pilab-dev/shadow-sso"
	"github.com/pilab-dev/shadow-sso/apps/ssso/config"
	"github.com/pilab-dev/shadow-sso/cache"
	"github.com/pilab-dev/shadow-sso/mongodb"
	"github.com/pilab-dev/shadow-sso/services"
	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"
)

// ServerOption configures the behavior of StartServer.
type ServerOption func(*ssso.SSOServerOptions)

// WithExtraMiddlewares adds Gin middlewares to the SSO server.
func WithExtraMiddlewares(mws ...gin.HandlerFunc) ServerOption {
	return func(opts *ssso.SSOServerOptions) {
		opts.ExtraMiddlewares = mws
	}
}

// StartServer initializes and starts the SSO HTTP server.
// It handles TokenSigner initialization, SSOServerOptions creation,
// and returns a running *http.Server.
// The caller is responsible for Shutdown().
func StartServer(cfg config.Config, repoProvider services.RepositoryProvider, extraOpts ...ServerOption) (*http.Server, error) {
	// Map internal config to public api.OpenIDProviderConfig
	oidcConfig := cfg.ToOpenIDProviderConfig()

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

	// Get encryption key for configuration service
	encryptionKey := cfg.ConfigEncryptionKey

	// Create SSOServerOptions
	opts := ssso.SSOServerOptions{
		Config:             oidcConfig,
		AppConfig:          &cfg,
		RepositoryProvider: repoProvider,
		TokenSigner:        tokenSigner,
		TokenCache: func() cache.TokenStore {
			if mongoRp, ok := repoProvider.(*mongodb.MongoRepositoryProvider); ok {
				return mongoRp.TokenStore(context.Background())
			}
			return cache.NewMemoryTokenStore(oidcConfig.AccessTokenTTL)
		}(),
		PkceRepository:     nil, // Let NewSSOServer default to in-memory
		FlowStore:          nil, // Let NewSSOServer default to in-memory
		UserSessionStore:   nil, // Let NewSSOServer default to in-memory
		EncryptionKey:      encryptionKey,
		ExtraMiddlewares:   nil,
	}

	// Apply functional options
	for _, opt := range extraOpts {
		opt(&opts)
	}

	// Initialize the SSO server router
	router, err := ssso.NewSSOServer(opts)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize SSO server: %w", err)
	}

	// Listen on the configured address to get the actual listening address
	listener, err := net.Listen("tcp", cfg.HTTPAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to listen on %s: %w", cfg.HTTPAddr, err)
	}

	srv := &http.Server{
		Addr:    listener.Addr().String(), // Store actual listening address
		Handler: router,
	}

	// Start the server in a goroutine
	go func() {
		log.Info().Str("addr", srv.Addr).Msg("SSO server starting")
		if err := srv.Serve(listener); err != nil && err != http.ErrServerClosed {
			log.Error().Err(err).Msg("Failed to start SSO server")
		}
	}()

	return srv, nil
}
