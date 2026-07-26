//nolint:tagliatelle
package ssso

import (
	"context" // For context.Background()
	"errors"
	"fmt"
	"time"

	"connectrpc.com/connect"                                                   // For connect.WithInterceptors
	"connectrpc.com/otelconnect"                                               // For OpenTelemetry Connect interceptor
	"github.com/gin-gonic/gin"                                                 // For *gin.Engine
	"github.com/pilab-dev/shadow-sso/api"                                      // For api.OpenIDProviderConfig
	"github.com/pilab-dev/shadow-sso/api/openidv2_1"                           // For api.NewOAuth2API
	"github.com/pilab-dev/shadow-sso/api/webauth"                              // For webauth.New, WebAuth login UI
	"github.com/pilab-dev/shadow-sso/apps/ssso/config"                         // For config.Config
	"github.com/pilab-dev/shadow-sso/cache"                                    // For cache.NewMemoryTokenStore
	"github.com/pilab-dev/shadow-sso/domain"
	"github.com/pilab-dev/shadow-sso/gen/proto/sso/v1/ssov1connect"           // For Connect-RPC service handlers
	"github.com/pilab-dev/shadow-sso/graphql"
	"github.com/pilab-dev/shadow-sso/internal/notifications"
	"github.com/pilab-dev/shadow-sso/internal/oidcflow" // Still needed for concrete in-memory store instantiation
	"github.com/pilab-dev/shadow-sso/middleware"
	"github.com/pilab-dev/shadow-sso/mongodb" // For mongodb.NewMongoRepositoryProvider
	pkgAuth "github.com/pilab-dev/shadow-sso/pkg/auth" // For auth.NewBcryptPasswordHasher
	"github.com/pilab-dev/shadow-sso/services" // For services.NewTokenSigner, services.NewDefaultServiceProvider
	"github.com/rs/zerolog/log"
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
	AppConfig          *config.Config            // Viper configuration
	RepositoryProvider services.RepositoryProvider
	TokenSigner        *services.TokenSigner
	TokenCache         cache.TokenStore
	PkceRepository     domain.PkceRepository
	FlowStore          domain.FlowStore
	UserSessionStore   domain.UserSessionStore
	EncryptionKey      string // For configuration service encryption
	CookieSigningSecret string // Secret for signing SSO session cookies
}

// NewSSOServer initializes and returns a configured Gin engine for the SSO server.
func NewSSOServer(opts SSOServerOptions) (*gin.Engine, error) {
	gin.SetMode(gin.ReleaseMode)

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
		AppConfig:          opts.AppConfig,
		TokenSigner:        tokenSigner,
		TokenCache:         tokenCache,
		PkceRepository:     pkceRepo,
		FlowStore:          flowStore,
		UserSessionStore:   userSessionStore,
		EncryptionKey:      opts.EncryptionKey,
	}

	serviceProvider, err := services.NewDefaultServiceProvider(spOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize service provider: %w", err)
	}

	// Initialize password hasher (moved here as it's a service)
	passwordHasher := pkgAuth.NewBcryptPasswordHasher(opts.Config.SecurityConfig.PasswordHashingCost)

	// Create OAuth2 API handlers
	oauth2API := openidv2_1.NewOAuth2API(&openidv2_1.OAuth2APIOptions{
		OAuthService:         serviceProvider.OAuthService(),
		JSKSService:          serviceProvider.JWKSService(),
		ClientService:        serviceProvider.ClientService(),
		PkceService:          serviceProvider.PKCEService(),
		Config:               opts.Config,
		FlowStore:            serviceProvider.FlowStore(),
		UserSessionStore:     serviceProvider.UserSessionStore(),
		UserRepo:             repoProvider.UserRepository(context.Background()),
		PasswordHasher:       passwordHasher,
		FederationService:    serviceProvider.FederationService(),
		TokenService:         serviceProvider.TokenService(),
		CookieSigningSecret:  opts.CookieSigningSecret,
	})

	// Setup Gin server
	router := gin.New()
	router.Use(gin.Recovery())
	router.Use(middleware.ZerologLogger())
	oauth2API.RegisterRoutes(router)

	// --- WebAuth login UI routes ---
	webauthConfig := &webauth.Config{
		BrandLogoURL:             "",
		BrandOrganizationName:    "",
		BrandPrimaryColor:        "",
		RateLimitMaxAttempts:     5,
		RateLimitLockoutDuration: 15 * time.Minute,
	}
	if opts.AppConfig != nil {
		webauthConfig.BrandLogoURL = opts.AppConfig.BrandLogoURL
		webauthConfig.BrandOrganizationName = opts.AppConfig.BrandOrganizationName
		webauthConfig.BrandPrimaryColor = opts.AppConfig.BrandPrimaryColor
		if opts.AppConfig.RateLimitMaxAttempts > 0 {
			webauthConfig.RateLimitMaxAttempts = opts.AppConfig.RateLimitMaxAttempts
		}
		if opts.AppConfig.RateLimitLockoutDuration > 0 {
			webauthConfig.RateLimitLockoutDuration = opts.AppConfig.RateLimitLockoutDuration
		}
	}

	webauthAPI := webauth.New(&webauth.Options{
		UserRepo:          repoProvider.UserRepository(context.Background()),
		PasswordHasher:    passwordHasher,
		FlowStore:         serviceProvider.FlowStore(),
		UserSessionStore:  serviceProvider.UserSessionStore(),
		IdPRepository:     repoProvider.IdPRepository(context.Background()),
		FederationService: serviceProvider.FederationService(),
		OAuthService:      serviceProvider.OAuthService(),
		TokenService:      serviceProvider.TokenService(),
		ClientService:     serviceProvider.ClientService(),
		Config:            webauthConfig,
		SSOCookieSecret:   opts.CookieSigningSecret,
	})

	router.GET("/login", webauthAPI.LoginPageHandler)
	router.POST("/login", webauthAPI.LoginSubmitHandler)
	router.GET("/login/:provider", webauthAPI.SocialLoginHandler)
	router.GET("/consent", webauthAPI.ConsentPageHandler)
	router.POST("/consent", webauthAPI.ConsentSubmitHandler)

	// ---------- Connect-RPC handlers ----------
	ctx := context.Background()

	tokenService := serviceProvider.TokenService()
	authInterceptor := middleware.NewAuthInterceptor(tokenService)
	authzInterceptor := middleware.NewAuthorizationInterceptor()
	otelConnectInterceptor, err := otelconnect.NewInterceptor()
	if err != nil {
		return nil, fmt.Errorf("failed to create OpenTelemetry Connect interceptor: %w", err)
	}

	interceptors := connect.WithInterceptors(
		otelConnectInterceptor, authInterceptor, authzInterceptor)

	connectPasswordHasher := pkgAuth.NewBcryptPasswordHasher(0)

	// Auth Service — used by frontend login
	authServer := services.NewAuthServer(
		opts.RepositoryProvider.UserRepository(ctx),
		opts.RepositoryProvider.SessionRepository(ctx),
		tokenService,
		connectPasswordHasher,
		serviceProvider.FlowStore(),
		serviceProvider.OAuthService(),
		serviceProvider.ClientService(),
	)
	authPath, authHandler := ssov1connect.NewAuthServiceHandler(authServer, interceptors)
	router.Any(authPath+"*action", gin.WrapH(authHandler))

	// User Service
	userServer := services.NewUserServer(
		opts.RepositoryProvider.UserRepository(ctx),
		connectPasswordHasher,
		nil,
	)
	userPath, userHandler := ssov1connect.NewUserServiceHandler(userServer, interceptors)
	router.Any(userPath+"*action", gin.WrapH(userHandler))

	// TwoFactor Service
	twoFactorServer := services.NewTwoFactorServer(
		opts.RepositoryProvider.UserRepository(ctx),
		connectPasswordHasher,
		serviceProvider.MFAService(),
		serviceProvider.PushMFAService(),
		"ShadowSSO",
	)
	twoFactorPath, twoFactorHandler := ssov1connect.NewTwoFactorServiceHandler(twoFactorServer, interceptors)
	router.Any(twoFactorPath+"*action", gin.WrapH(twoFactorHandler))

	// Client Management Service
	clientManagementServer := services.NewClientManagementServer(
		opts.RepositoryProvider.ClientRepository(ctx),
		connectPasswordHasher,
	)
	clientPath, clientHandler := ssov1connect.NewClientManagementServiceHandler(clientManagementServer, interceptors)
	router.Any(clientPath+"*action", gin.WrapH(clientHandler))

	// IDP Management Service
	idpManagementServer := services.NewIdPManagementServer(
		opts.RepositoryProvider.IdPRepository(ctx),
	)
	idpPath, idpHandler := ssov1connect.NewIdPManagementServiceHandler(idpManagementServer, interceptors)
	router.Any(idpPath+"*action", gin.WrapH(idpHandler))

	// Service Account Service
	defaultKeyGen := &services.DefaultSAKeyGenerator{}
	saServer := services.NewServiceAccountServer(
		defaultKeyGen,
		opts.RepositoryProvider.ServiceAccountRepository(ctx),
		opts.RepositoryProvider.PublicKeyRepository(ctx),
	)
	saPath, saHandler := ssov1connect.NewServiceAccountServiceHandler(saServer, interceptors)
	router.Any(saPath+"*action", gin.WrapH(saHandler))

	// Federation Service
	federationServer := services.NewFederationServer(
		serviceProvider.FederationService(),
		opts.RepositoryProvider.UserRepository(ctx),
		opts.RepositoryProvider.UserFederatedIdentityRepository(ctx),
		opts.RepositoryProvider.IdPRepository(ctx),
		tokenService,
		opts.RepositoryProvider.SessionRepository(ctx),
		connectPasswordHasher,
	)
	federationPath, federationHandler := ssov1connect.NewFederationServiceHandler(federationServer, interceptors)
	router.Any(federationPath+"*action", gin.WrapH(federationHandler))

	log.Info().Msg("Connect-RPC handlers registered successfully")
	// ---------- End Connect-RPC handlers ----------

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

	// --- GraphQL API wiring ---
	if mongoRp, ok := repoProvider.(*mongodb.MongoRepositoryProvider); ok {
		db := mongoRp.Database()
		gqlCtx := context.Background()

		userRepo, _ := mongodb.NewUserRepository(gqlCtx, db)
		clientRepo := mongodb.NewClientRepository(db)
		sessionRepo, _ := mongodb.NewSessionRepositoryMongo(gqlCtx, db)
		idpRepo, _ := mongodb.NewIdPRepositoryMongo(gqlCtx, db)
		groupRepo, _ := mongodb.NewGroupRepository(gqlCtx, db)
		roleRepo, _ := mongodb.NewRoleRepository(gqlCtx, db)
		protocolMapperRepo, _ := mongodb.NewProtocolMapperRepository(gqlCtx, db)
		authFlowRepo, _ := mongodb.NewAuthenticationFlowRepository(gqlCtx, db)
		clientScopeRepo, _ := mongodb.NewClientScopeRepository(gqlCtx, db)
		realmSettingsRepo, _ := mongodb.NewRealmSettingsRepository(gqlCtx, db)
		realmKeysRepo, _ := mongodb.NewRealmKeysRepository(gqlCtx, db)
		userAttrRepo, _ := mongodb.NewUserAttributeRepository(gqlCtx, db)
		userAttrMapperRepo, _ := mongodb.NewUserAttributeMapperRepository(gqlCtx, db)

		var emailService domain.EmailService
		if opts.AppConfig != nil {
			emailService = notifications.NewResendEmailService(
				opts.AppConfig.ResendAPIKey,
				opts.AppConfig.FromEmail,
				opts.AppConfig.NextPublicBaseURL,
			)
		} else {
			emailService = notifications.NewResendEmailService("", "", "")
		}

		resolver := &graphql.Resolver{
			UserRepo:                userRepo,
			UserAttributeRepo:       userAttrRepo,
			UserAttributeMapperRepo: userAttrMapperRepo,
			ClientRepo:              clientRepo,
			SessionRepo:             sessionRepo,
			IdPRepo:                 idpRepo,
			GroupRepo:               groupRepo,
			RoleRepo:                roleRepo,
			ProtocolMapperRepo:      protocolMapperRepo,
			AuthFlowRepo:            authFlowRepo,
			ClientScopeRepo:         clientScopeRepo,
			RealmSettingsRepo:       realmSettingsRepo,
			RealmKeysRepo:           realmKeysRepo,
			EmailService:            emailService,
			PasswordHasher:          passwordHasher,
		}

		graphqlHandler := graphql.AuthMiddleware(
			serviceProvider.TokenService(),
			graphql.NewHandler(resolver, "/graphql", graphql.GraphQLConfig{IsDevelopment: true}),
		)

		router.POST("/graphql", gin.WrapH(graphqlHandler))
		router.GET("/sandbox", gin.WrapH(graphql.SandboxHandler("/graphql")))
	}

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
