//nolint:tagliatelle
package ssso

import (
	"context" // For context.Background()
	"errors"
	"fmt"
	"time"

	"github.com/gin-gonic/gin" // For *gin.Engine
	"github.com/pilab-dev/shadow-sso/api" // For api.OpenIDProviderConfig
	"github.com/pilab-dev/shadow-sso/api/openidv2_1" // For api.NewOAuth2API
	"github.com/pilab-dev/shadow-sso/cache" // For cache.NewMemoryTokenStore
	"github.com/pilab-dev/shadow-sso/domain"
	"github.com/pilab-dev/shadow-sso/internal/oidcflow" // Still needed for concrete in-memory store instantiation
	"github.com/pilab-dev/shadow-sso/mongodb" // For mongodb.NewMongoRepositoryProvider
	pkgAuth "github.com/pilab-dev/shadow-sso/pkg/auth" // For auth.NewBcryptPasswordHasher
	"github.com/pilab-dev/shadow-sso/services" // For services.NewTokenSigner, services.NewDefaultServiceProvider
	"sync" // For InMemoryPkceRepository
)

// NewInMemoryFlowStore creates a new in-memory implementation of domain.FlowStore.
// This is suitable for development and testing environments.
func NewInMemoryFlowStore() domain.FlowStore {
	return oidcflow.NewInMemoryFlowStore()
}

// NewInMemoryUserSessionStore creates a new in-memory implementation of domain.UserSessionStore.
// This is suitable for development and testing environments.
func NewInMemoryUserSessionStore() domain.UserSessionStore {
	return oidcflow.NewInMemoryUserSessionStore()
}

// NewMongoRepositoryProvider creates a new services.RepositoryProvider backed by MongoDB.
// It connects to the specified MongoDB URI and uses the given database name.
func NewMongoRepositoryProvider(mongoURI, dbName string) (services.RepositoryProvider, error) {
	return mongodb.NewMongoRepositoryProvider(mongoURI, dbName)
}

// InMemoryPkceRepository implements domain.PkceRepository for testing and development.
type InMemoryPkceRepository struct {
	codes map[string]string
	mu    sync.RWMutex
}

// NewInMemoryPkceRepository creates a new in-memory PKCE repository.
func NewInMemoryPkceRepository() domain.PkceRepository {
	return &InMemoryPkceRepository{
		codes: make(map[string]string),
	}
}

// SaveCodeChallenge stores a code and its challenge.
func (r *InMemoryPkceRepository) SaveCodeChallenge(ctx context.Context, code, challenge string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.codes[code] = challenge
	return nil
}

// GetCodeChallenge retrieves the challenge for a given code.
func (r *InMemoryPkceRepository) GetCodeChallenge(ctx context.Context, code string) (string, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	challenge, ok := r.codes[code]
	if !ok {
		return "", fmt.Errorf("code challenge not found for code: %s", code)
	}
	return challenge, nil
}

// DeleteCodeChallenge removes a code and its challenge.
func (r *InMemoryPkceRepository) DeleteCodeChallenge(ctx context.Context, code string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.codes, code)
	return nil
}

// OpenIDProviderConfig is now in the api package
// Use api.OpenIDProviderConfig instead

// SSOServerOptions provides options for configuring the NewSSOServer function.
type SSOServerOptions struct {
	Config             *api.OpenIDProviderConfig
	RepositoryProvider services.RepositoryProvider
	TokenSigner        *services.TokenSigner
	TokenCache         cache.TokenStore
	PkceRepository     domain.PkceRepository
	FlowStore          domain.FlowStore
	UserSessionStore   domain.UserSessionStore
}

// NewSSOServer initializes and returns a configured Gin engine for the SSO server.
func NewSSOServer(opts SSOServerOptions) (*gin.Engine, error) {
	if opts.Config == nil {
		return nil, errors.New("OpenIDProviderConfig is required")
	}

	// Initialize RepositoryProvider
	var repoProvider services.RepositoryProvider
	if opts.RepositoryProvider != nil {
		repoProvider = opts.RepositoryProvider
	} else {
		// Default to MongoDB if not provided
		// Assuming config has MongoURI and MongoDBName. This should be part of app-level config.
		// For now, hardcoding for example purposes, but this should come from opts.Config or dedicated server config.
		// A better approach would be to pass a context.Context to the repository provider factory if it needs to connect.
		var err error
		repoProvider, err = mongodb.NewMongoRepositoryProvider("mongodb://localhost:27017", "shadow_sso_db")
		if err != nil {
			return nil, fmt.Errorf("failed to initialize default MongoDB repository provider: %w", err)
		}
	}

	// Initialize TokenSigner
	tokenSigner := opts.TokenSigner
	if tokenSigner == nil {
		// Default token signer (e.g., with a generated key for HS256 for simplicity in example, or from file)
		tokenSigner = services.NewTokenSigner()
		// For a real setup, this key should be loaded securely
		tokenSigner.AddKeySigner("super-secret-default-key-replace-me-in-production")
	}

	// Initialize TokenCache
	tokenCache := opts.TokenCache
	// Note: In-memory token store was removed. TokenCache must be provided in opts.
	if tokenCache == nil {
		return nil, errors.New("TokenCache is required (in-memory implementation was removed)")
	}

	// Initialize PKCE Repository
	pkceRepo := opts.PkceRepository
	if pkceRepo == nil {
		pkceRepo = NewInMemoryPkceRepository()
	}

	// Initialize FlowStore
	flowStore := opts.FlowStore
	if flowStore == nil {
		flowStore = NewInMemoryFlowStore()
	}

	// Initialize UserSessionStore
	userSessionStore := opts.UserSessionStore
	if userSessionStore == nil {
		userSessionStore = NewInMemoryUserSessionStore()
	}

	// Create DefaultServiceProviderOptions
	spOpts := services.DefaultServiceProviderOptions{
		RepositoryProvider: repoProvider,
		Config:             opts.Config,
		TokenSigner:        tokenSigner,
		TokenCache:         tokenCache,
		PkceRepository:     pkceRepo,
		FlowStore:          flowStore,
		UserSessionStore:   userSessionStore,
	}

	serviceProvider, err := services.NewDefaultServiceProvider(spOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize service provider: %w", err)
	}

	// Initialize password hasher (moved here as it's a service)
	passwordHasher := pkgAuth.NewBcryptPasswordHasher(opts.Config.SecurityConfig.PasswordHashingCost)

	// Create OAuth2 API handlers
	oauth2API := openidv2_1.NewOAuth2API(&openidv2_1.OAuth2APIOptions{
		OAuthService:      serviceProvider.OAuthService(),
		JSKSService:       serviceProvider.JWKSService(),
		ClientService:     serviceProvider.ClientService(),
		PkceService:       serviceProvider.PKCEService(),
		Config:            opts.Config,
		FlowStore:         serviceProvider.FlowStore(),
		UserSessionStore:  serviceProvider.UserSessionStore(),
		UserRepo:          repoProvider.UserRepository(context.Background()),
		PasswordHasher:   passwordHasher,
		FederationService: serviceProvider.FederationService(),
		TokenService:      serviceProvider.TokenService(),
	})

	// Setup Gin server
	router := gin.Default()
	oauth2API.RegisterRoutes(router)

	// Add health check endpoint
	router.GET("/healthz", func(c *gin.Context) {
		c.String(200, "OK")
	})

	// Add readiness check endpoint - verifies MongoDB connection
	router.GET("/readyz", func(c *gin.Context) {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()

		// Try to ping MongoDB if using MongoDB repository provider
		if mongoRp, ok := repoProvider.(*mongodb.MongoRepositoryProvider); ok {
			if err := mongoRp.Ping(ctx); err != nil {
				c.String(503, "Service Unavailable: MongoDB connection failed")
				return
			}
		}
		// If we got here, MongoDB is accessible (or not using MongoDB)
		c.String(200, "OK")
	})

	return router, nil
}


var (
	ErrInvalidConfig       = errors.New("invalid configuration")
	ErrInvalidScopeRequest = errors.New("invalid scope request")
)

// ValidateConfig checks if the configuration is valid
func ValidateConfig(c *api.OpenIDProviderConfig) error {
	if c.Issuer == "" {
		return fmt.Errorf("%w: issuer cannot be empty", ErrInvalidConfig)
	}

	if c.AccessTokenTTL <= 0 {
		return fmt.Errorf("%w: access token TTL must be positive", ErrInvalidConfig)
	}

	if c.RefreshTokenTTL <= 0 {
		return fmt.Errorf("%w: refresh token TTL must be positive", ErrInvalidConfig)
	}

	if c.AuthCodeTTL <= 0 {
		return fmt.Errorf("%w: auth code TTL must be positive", ErrInvalidConfig)
	}

	if len(c.SecurityConfig.AllowedSigningAlgs) == 0 {
		return fmt.Errorf("%w: at least one signing algorithm must be allowed", ErrInvalidConfig)
	}

	if c.TokenConfig.AccessTokenFormat != "jwt" && c.TokenConfig.AccessTokenFormat != "opaque" {
		return fmt.Errorf("%w: invalid access token format: %s",
			ErrInvalidConfig,
			c.TokenConfig.AccessTokenFormat)
	}

	return nil
}

// IsGrantTypeEnabled checks if a specific grant type is enabled
func IsGrantTypeEnabled(c *api.OpenIDProviderConfig, grantType string) bool {
	switch grantType {
	case "authorization_code":
		return c.EnabledGrantTypes.AuthorizationCode
	case "client_credentials":
		return c.EnabledGrantTypes.ClientCredentials
	case "refresh_token":
		return c.EnabledGrantTypes.RefreshToken
	case "password":
		return c.EnabledGrantTypes.Password
	case "implicit":
		return c.EnabledGrantTypes.Implicit
	case "urn:ietf:params:oauth:grant-type:jwt-bearer":
		return c.EnabledGrantTypes.JWTBearer
	case "urn:ietf:params:oauth:grant-type:device_code":
		return c.EnabledGrantTypes.DeviceCode
	default:
		return false
	}
}

// IsEndpointEnabled checks if a specific endpoint is enabled
func IsEndpointEnabled(c *api.OpenIDProviderConfig, endpoint string) bool {
	switch endpoint {
	case "authorization":
		return c.EnabledEndpoints.Authorization
	case "token":
		return c.EnabledEndpoints.Token
	case "userinfo":
		return c.EnabledEndpoints.UserInfo
	case "jwks":
		return c.EnabledEndpoints.JWKS
	case "registration":
		return c.EnabledEndpoints.Registration
	case "revocation":
		return c.EnabledEndpoints.Revocation
	case "introspection":
		return c.EnabledEndpoints.Introspection
	case "end_session":
		return c.EnabledEndpoints.EndSession
	default:
		return false
	}
}
