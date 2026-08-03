package server

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	ssso "github.com/pilab-dev/shadow-sso"
	"github.com/pilab-dev/shadow-sso/apps/ssso/config"
	"github.com/pilab-dev/shadow-sso/cache"
	"github.com/pilab-dev/shadow-sso/domain"
	"github.com/pilab-dev/shadow-sso/internal/telemetry"
	"github.com/pilab-dev/shadow-sso/mongodb"
	pkgcrypto "github.com/pilab-dev/shadow-sso/pkg/crypto"
	"github.com/pilab-dev/shadow-sso/services"
	"github.com/rs/zerolog/log"
)

// HTTP server timeouts for the main externally-facing OAuth2/OIDC server.
// Bounds slow-client (Slowloris-style) resource exhaustion; ReadTimeout and
// WriteTimeout are generous to accommodate slow clients on legitimate but
// slow connections (e.g. device flow polling, large token requests).
const (
	httpReadHeaderTimeout = 3 * time.Second
	httpReadTimeout       = 5 * time.Minute
	httpWriteTimeout      = 5 * time.Minute
	httpIdleTimeout       = 120 * time.Second
	httpMaxHeaderBytes    = 8 * 1024 // 8KiB
)

// ServerOption configures the behavior of StartServer.
type ServerOption func(*ssso.SSOServerOptions)

// WithExtraMiddlewares adds Gin middlewares to the SSO server.
func WithExtraMiddlewares(mws ...gin.HandlerFunc) ServerOption {
	return func(opts *ssso.SSOServerOptions) {
		opts.ExtraMiddlewares = mws
	}
}

// insecureDevSigningSecret is only ever used when SSSO_ALLOW_INSECURE_DEFAULTS=true,
// which must never be set in production.
const insecureDevSigningSecret = "temporary-secret-for-hs256-change-me"

func newTokenSigner(cfg config.Config) (*services.TokenSigner, error) {
	tokenSigner := services.NewTokenSigner()
	if cfg.SigningKeyPath != "" {
		if err := tokenSigner.AddRSASigner(cfg.SigningKeyPath); err != nil {
			if !cfg.AllowInsecureDefaults {
				return nil, fmt.Errorf("failed to load RSA signing key from %q: %w (set SSSO_ALLOW_INSECURE_DEFAULTS=true to fall back to an insecure HS256 secret for local development only)", cfg.SigningKeyPath, err)
			}
			log.Warn().Err(err).Str("path", cfg.SigningKeyPath).Msg("Failed to load RSA signing key, falling back to insecure dev HS256 secret")
			tokenSigner.AddKeySigner(insecureDevSigningSecret)
		} else {
			log.Info().Msg("RSA signing key loaded successfully (RS256)")
		}
	} else if cfg.TokenSigningKey != "" {
		tokenSigner.AddKeySigner(cfg.TokenSigningKey)
		log.Info().Msg("Token signing key loaded from config (HS256).")
	} else {
		if !cfg.AllowInsecureDefaults {
			return nil, fmt.Errorf("no token signing key configured: set SSSO_SIGNING_KEY_PATH or SSSO_TOKEN_SIGNING_KEY (or SSSO_ALLOW_INSECURE_DEFAULTS=true for local development only)")
		}
		log.Warn().Msg("No token signing key configured. Using insecure dev placeholder - REPLACE IN PRODUCTION.")
		tokenSigner.AddKeySigner(insecureDevSigningSecret)
	}
	return tokenSigner, nil
}

// bootstrapRegistrySigner upgrades the file/env-configured TokenSigner to the
// DB-backed signing key registry. On first run with an RSA signing key it
// imports that key as the realm-default active key; on later runs the registry
// is the source of truth and env/file keys are never consulted again. When
// registry mode is not possible it returns the original signer unchanged.
func bootstrapRegistrySigner(ctx context.Context, cfg config.Config, repoProvider services.RepositoryProvider, tokenSigner *services.TokenSigner) *services.TokenSigner {
	// Private keys are encrypted at rest with ConfigEncryptionKey (32 raw
	// bytes). The auto-generated ephemeral dev key is hex-encoded and changes
	// every boot; persisting with it would make stored keys permanently
	// undecryptable, so never seed with it.
	if len(cfg.ConfigEncryptionKey) != 32 {
		log.Warn().Msg("DB-backed signing key registry disabled: ConfigEncryptionKey must be exactly 32 bytes for key-at-rest encryption")
		return tokenSigner
	}
	if !tokenSigner.HasRSASigner() {
		return tokenSigner
	}
	repo := repoProvider.RealmKeysRepository(ctx)
	if repo == nil {
		log.Info().Msg("DB-backed signing key registry disabled: RealmKeysRepository unavailable")
		return tokenSigner
	}

	keys, err := repo.ListAllKeys(ctx)
	if err != nil {
		log.Error().Err(err).Msg("Failed to list realm signing keys, falling back to configured signing key")
		return tokenSigner
	}
	if len(keys) == 0 {
		if err := seedRealmDefaultKey(ctx, cfg, repo, tokenSigner); err != nil {
			log.Error().Err(err).Msg("Failed to seed realm signing key, falling back to configured signing key")
			return tokenSigner
		}
	}
	if err := tokenSigner.LoadFromRepository(ctx, repo, []byte(cfg.ConfigEncryptionKey)); err != nil {
		log.Error().Err(err).Msg("Failed to load signing keys from repository, falling back to configured signing key")
		return tokenSigner
	}

	interval := cfg.KeyRotationInterval
	if interval <= 0 {
		interval = 24 * time.Hour
	}
	tokenSigner.StartKeyRefresh(ctx, interval)
	log.Info().Msg("DB-backed signing key registry active")
	return tokenSigner
}

// seedRealmDefaultKey imports the configured RSA signing key as the
// realm-default active key on first run, encrypted at rest with the
// ConfigEncryptionKey.
func seedRealmDefaultKey(ctx context.Context, cfg config.Config, repo domain.RealmKeysRepository, tokenSigner *services.TokenSigner) error {
	privPEM, err := tokenSigner.ExportRSAPrivateKeyPEM()
	if err != nil {
		return fmt.Errorf("failed to export RSA signing key: %w", err)
	}
	privKey := tokenSigner.GetRSAPrivateKey()
	if privKey == nil {
		return fmt.Errorf("failed to resolve RSA signing key")
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	if err != nil {
		return fmt.Errorf("failed to encode RSA public key: %w", err)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})

	encPriv, err := pkgcrypto.EncryptAESGCM([]byte(cfg.ConfigEncryptionKey), string(privPEM))
	if err != nil {
		return fmt.Errorf("failed to encrypt signing key at rest: %w", err)
	}

	return repo.SaveRealmKey(ctx, &domain.RealmKey{
		Name:      "realm-default",
		Type:      "RSA",
		Active:    true,
		Priority:  1,
		PublicKey: string(pubPEM),
		// PrivateKey holds the encrypted PEM; ClientID is empty because this is
		// the realm-default signing key, not a per-client key.
		PrivateKey: encPriv,
		Status:     domain.RealmKeyStatusActive,
	})
}

// StartServer initializes and starts the SSO HTTP server.
// It handles TokenSigner initialization, SSOServerOptions creation,
// and returns a running *http.Server.
// The caller is responsible for Shutdown().
func StartServer(ctx context.Context, cfg config.Config, repoProvider services.RepositoryProvider, extraOpts ...ServerOption) (*http.Server, error) {
	ctx, span := telemetry.StartSpan(ctx, "shadow-sso", "server.start")
	defer span.End()
	// Map internal config to public api.OpenIDProviderConfig
	oidcConfig := cfg.ToOpenIDProviderConfig()

	// Initialize TokenSigner (potentially from file/env)
	tokenSigner, err := newTokenSigner(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize token signer: %w", err)
	}

	// Upgrade to the DB-backed signing key registry when possible; keeps the
	// legacy signer otherwise.
	tokenSigner = bootstrapRegistrySigner(context.Background(), cfg, repoProvider, tokenSigner)

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
		PkceRepository:   nil, // Let NewSSOServer default to in-memory
		FlowStore:        nil, // Let NewSSOServer default to in-memory
		UserSessionStore: nil, // Let NewSSOServer default to in-memory
		EncryptionKey:    encryptionKey,
		ExtraMiddlewares: nil,
	}

	// Apply functional options
	for _, opt := range extraOpts {
		opt(&opts)
	}

	// Initialize the SSO server router
	router, err := ssso.NewSSOServer(ctx, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize SSO server: %w", err)
	}

	// Listen on the configured address to get the actual listening address
	listener, err := net.Listen("tcp", cfg.HTTPAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to listen on %s: %w", cfg.HTTPAddr, err)
	}

	srv := &http.Server{
		Addr:              listener.Addr().String(), // Store actual listening address
		Handler:           router,
		ReadHeaderTimeout: httpReadHeaderTimeout,
		ReadTimeout:       httpReadTimeout,
		WriteTimeout:      httpWriteTimeout,
		IdleTimeout:       httpIdleTimeout,
		MaxHeaderBytes:    httpMaxHeaderBytes,
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
