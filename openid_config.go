//nolint:tagliatelle
package ssso

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"connectrpc.com/connect"
	"connectrpc.com/otelconnect"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/pilab-dev/shadow-sso/api"
	"github.com/pilab-dev/shadow-sso/api/openidv2_1"
	"github.com/pilab-dev/shadow-sso/api/webauth"
	"github.com/pilab-dev/shadow-sso/apps/ssso/config"
	"github.com/pilab-dev/shadow-sso/cache"
	"github.com/pilab-dev/shadow-sso/domain"
	"github.com/pilab-dev/shadow-sso/gen/proto/sso/v1/ssov1connect"
	"github.com/pilab-dev/shadow-sso/graphql"
	"github.com/pilab-dev/shadow-sso/internal/audit"
	"github.com/pilab-dev/shadow-sso/internal/notifications"
	"github.com/pilab-dev/shadow-sso/internal/oidcflow"
	"github.com/pilab-dev/shadow-sso/internal/oidclogout"
	"github.com/pilab-dev/shadow-sso/internal/telemetry"
	"github.com/pilab-dev/shadow-sso/middleware"
	"github.com/pilab-dev/shadow-sso/mongodb"
	pkgAuth "github.com/pilab-dev/shadow-sso/pkg/auth"
	"github.com/pilab-dev/shadow-sso/services"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
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
	Config              *api.OpenIDProviderConfig
	AppConfig           *config.Config // Viper configuration
	RepositoryProvider  services.RepositoryProvider
	TokenSigner         *services.TokenSigner
	TokenCache          cache.TokenStore
	PkceRepository      domain.PkceRepository
	FlowStore           domain.FlowStore
	UserSessionStore    domain.UserSessionStore
	EncryptionKey       string            // For configuration service encryption
	CookieSigningSecret string            // Secret for signing SSO session cookies
	ExtraMiddlewares    []gin.HandlerFunc // Additional Gin middlewares applied before route registration
}

// NewSSOServer initializes and returns a configured Gin engine for the SSO server.
func NewSSOServer(ctx context.Context, opts SSOServerOptions) (*gin.Engine, error) {
	ctx, span := telemetry.StartSpan(ctx, "shadow-sso", "NewSSOServer")
	defer span.End()

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

	// Install the async audit persistence sink so audit.Log events are also
	// written to the repository without blocking the auth path. Fire-and-forget:
	// a slow or unavailable MongoDB never delays or fails the caller.
	audit.SetSink(repoProvider.AuditLogRepository(context.Background()))

	// Initialize TokenSigner
	tokenSigner := opts.TokenSigner
	if tokenSigner == nil {
		if opts.AppConfig == nil || !opts.AppConfig.AllowInsecureDefaults {
			return nil, errors.New("TokenSigner is required (set SSSO_ALLOW_INSECURE_DEFAULTS=true to fall back to an insecure placeholder key for local development only)")
		}
		log.Warn().Msg("No TokenSigner provided. Using insecure dev placeholder key - REPLACE IN PRODUCTION.")
		tokenSigner = services.NewTokenSigner()
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
		if mongoRp, ok := repoProvider.(*mongodb.MongoRepositoryProvider); ok {
			pkceRepo = mongoRp.PkceRepository(context.Background())
		}
	}
	if pkceRepo == nil {
		pkceRepo = NewInMemoryPkceRepository()
	}

	// Initialize FlowStore
	flowStore := opts.FlowStore
	if flowStore == nil {
		if mongoRp, ok := repoProvider.(*mongodb.MongoRepositoryProvider); ok {
			flowStore = mongoRp.FlowStore(context.Background())
		}
	}
	if flowStore == nil {
		flowStore = NewInMemoryFlowStore()
	}

	// Initialize UserSessionStore
	userSessionStore := opts.UserSessionStore
	if userSessionStore == nil {
		if mongoRp, ok := repoProvider.(*mongodb.MongoRepositoryProvider); ok {
			userSessionStore = mongoRp.UserSessionStore(context.Background())
		}
	}
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

	_, spSpan := telemetry.StartSpan(ctx, "shadow-sso", "NewSSOServer.serviceProvider")
	serviceProvider, err := services.NewDefaultServiceProvider(spOpts)
	spSpan.End()
	if err != nil {
		return nil, fmt.Errorf("failed to initialize service provider: %w", err)
	}

	// Seed realm settings from config on first boot so grant paths read the
	// persisted AccessTokenLifespan/AccessCodeLifespan instead of hardcoded
	// values. No-op once the realm_settings collection already holds documents.
	if err := seedRealmSettingsFromConfig(repoProvider, opts.Config); err != nil {
		return nil, err
	}

	// Bootstrap the built-in public "sssoctl" OAuth client used by the ssoctl
	// CLI device-code login flow. Create-if-missing only: an existing client
	// with that ID is never modified.
	if err := ensureBootstrapSSSOCTLClient(ctx, repoProvider.ClientRepository(context.Background()), log.Logger); err != nil {
		return nil, err
	}

	// Initialize password hasher (moved here as it's a service)
	passwordHasher := pkgAuth.NewBcryptPasswordHasher(opts.Config.SecurityConfig.PasswordHashingCost)

	var brandLogoURL, brandOrgName, brandColor, bootstrapToken string
	if opts.AppConfig != nil {
		brandLogoURL = opts.AppConfig.BrandLogoURL
		brandOrgName = opts.AppConfig.BrandOrganizationName
		brandColor = opts.AppConfig.BrandPrimaryColor
		bootstrapToken = opts.AppConfig.BootstrapToken
	}

	// Create OAuth2 API handlers
	oauth2API := openidv2_1.NewOAuth2API(&openidv2_1.OAuth2APIOptions{
		OAuthService:          serviceProvider.OAuthService(),
		JSKSService:           serviceProvider.JWKSService(),
		ClientService:         serviceProvider.ClientService(),
		PkceService:           serviceProvider.PKCEService(),
		Config:                opts.Config,
		FlowStore:             serviceProvider.FlowStore(),
		UserSessionStore:      serviceProvider.UserSessionStore(),
		UserRepo:              repoProvider.UserRepository(context.Background()),
		PasswordHasher:        passwordHasher,
		FederationService:     serviceProvider.FederationService(),
		TokenService:          serviceProvider.TokenService(),
		RealmKeysRepo:         repoProvider.RealmKeysRepository(context.Background()),
		ClientRepo:            repoProvider.ClientRepository(context.Background()),
		CookieSigningSecret:   opts.CookieSigningSecret,
		TokenSigner:           tokenSigner,
		SessionRepo:           repoProvider.SessionRepository(context.Background()),
		BootstrapToken:        bootstrapToken,
		BrandLogoURL:          brandLogoURL,
		BrandOrganizationName: brandOrgName,
		BrandPrimaryColor:     brandColor,
		BackchannelLogoutNotifier: oidclogout.NewNotifier(opts.Config.Issuer, func(claims jwt.Claims) (string, error) {
			return tokenSigner.Sign(claims, "")
		}),
	})

	// Setup Gin server
	router := gin.New()
	router.Use(gin.Recovery())
	router.Use(middleware.ZerologLogger())

	// Apply extra middlewares (CORS, request ID, tracing, etc.)
	for _, m := range opts.ExtraMiddlewares {
		router.Use(m)
	}

	if err := webauth.LoadTemplates(router); err != nil {
		return nil, fmt.Errorf("failed to load webauth templates: %w", err)
	}
	oauth2API.RegisterRoutes(router)

	// --- WebAuth login UI routes ---
	webauthConfig := &webauth.Config{
		BrandLogoURL:             brandLogoURL,
		BrandOrganizationName:    brandOrgName,
		BrandPrimaryColor:        brandColor,
		RateLimitMaxAttempts:     5,
		RateLimitLockoutDuration: 15 * time.Minute,
	}
	if opts.AppConfig != nil {
		if opts.AppConfig.RateLimitMaxAttempts > 0 {
			webauthConfig.RateLimitMaxAttempts = opts.AppConfig.RateLimitMaxAttempts
		}
		if opts.AppConfig.RateLimitLockoutDuration > 0 {
			webauthConfig.RateLimitLockoutDuration = opts.AppConfig.RateLimitLockoutDuration
		}
	}

	var authFlowRepo domain.AuthenticationFlowRepository
	if mongoRp, ok := repoProvider.(*mongodb.MongoRepositoryProvider); ok {
		authFlowRepo = mongoRp.AuthenticationFlowRepository(context.Background())
	}

	webauthAPI := webauth.New(&webauth.Options{
		UserRepo:           repoProvider.UserRepository(context.Background()),
		PasswordHasher:     passwordHasher,
		FlowStore:          serviceProvider.FlowStore(),
		UserSessionStore:   serviceProvider.UserSessionStore(),
		IdPRepository:      repoProvider.IdPRepository(context.Background()),
		FederationService:  serviceProvider.FederationService(),
		OAuthService:       serviceProvider.OAuthService(),
		TokenService:       serviceProvider.TokenService(),
		ClientService:      serviceProvider.ClientService(),
		Config:             webauthConfig,
		SSOCookieSecret:    opts.CookieSigningSecret,
		AuthFlowRepo:       authFlowRepo,
		RealmSettingsRepo:  repoProvider.RealmSettingsRepository(context.Background()),
	})

	router.GET("/", webauthAPI.LandingPageHandler)
	router.GET("/login", webauthAPI.LoginPageHandler)
	router.POST("/login", webauthAPI.LoginSubmitHandler)
	router.GET("/login/:provider", webauthAPI.SocialLoginHandler)
	router.GET("/consent", webauthAPI.ConsentPageHandler)
	router.POST("/consent", webauthAPI.ConsentSubmitHandler)
	// ---------- Connect-RPC handlers ----------
	connectCtx, connectSpan := telemetry.StartSpan(ctx, "shadow-sso", "NewSSOServer.connectrpc")
	defer connectSpan.End()

	tokenService := serviceProvider.TokenService()
	authInterceptor := middleware.NewAuthInterceptor(tokenService)
	authzInterceptor := middleware.NewAuthorizationInterceptor()
	otelConnectInterceptor, err := otelconnect.NewInterceptor()
	if err != nil {
		return nil, fmt.Errorf("failed to create OpenTelemetry Connect interceptor: %w", err)
	}

	interceptors := connect.WithInterceptors(
		otelConnectInterceptor, authInterceptor, authzInterceptor)

	// Auth Service — used by frontend login
	authServer := services.NewAuthServer(
		opts.RepositoryProvider.UserRepository(connectCtx),
		opts.RepositoryProvider.SessionRepository(connectCtx),
		tokenService,
		passwordHasher,
		serviceProvider.FlowStore(),
		serviceProvider.OAuthService(),
		serviceProvider.ClientService(),
	)
	authPath, authHandler := ssov1connect.NewAuthServiceHandler(authServer, interceptors)
	router.Any(authPath+"*action", gin.WrapH(authHandler))

	// User Service
	userServer := services.NewUserServer(
		opts.RepositoryProvider.UserRepository(connectCtx),
		passwordHasher,
		nil,
		services.WithUserRealmSettings(opts.RepositoryProvider.RealmSettingsRepository(ctx)),
	)
	userPath, userHandler := ssov1connect.NewUserServiceHandler(userServer, interceptors)
	router.Any(userPath+"*action", gin.WrapH(userHandler))

	// TwoFactor Service
	twoFactorServer := services.NewTwoFactorServer(
		opts.RepositoryProvider.UserRepository(connectCtx),
		passwordHasher,
		serviceProvider.MFAService(),
		serviceProvider.PushMFAService(),
		"ShadowSSO",
	)
	twoFactorPath, twoFactorHandler := ssov1connect.NewTwoFactorServiceHandler(twoFactorServer, interceptors)
	router.Any(twoFactorPath+"*action", gin.WrapH(twoFactorHandler))

	// Client Management Service
	clientManagementServer := services.NewClientManagementServer(
		opts.RepositoryProvider.ClientRepository(connectCtx),
		passwordHasher,
	)
	clientPath, clientHandler := ssov1connect.NewClientManagementServiceHandler(clientManagementServer, interceptors)
	router.Any(clientPath+"*action", gin.WrapH(clientHandler))

	// IDP Management Service
	idpManagementServer := services.NewIdPManagementServer(
		opts.RepositoryProvider.IdPRepository(connectCtx),
	)
	idpPath, idpHandler := ssov1connect.NewIdPManagementServiceHandler(idpManagementServer, interceptors)
	router.Any(idpPath+"*action", gin.WrapH(idpHandler))

	// Service Account Service
	defaultKeyGen := &services.DefaultSAKeyGenerator{}
	saServer := services.NewServiceAccountServer(
		defaultKeyGen,
		opts.RepositoryProvider.ServiceAccountRepository(connectCtx),
		opts.RepositoryProvider.PublicKeyRepository(connectCtx),
	)
	saPath, saHandler := ssov1connect.NewServiceAccountServiceHandler(saServer, interceptors)
	router.Any(saPath+"*action", gin.WrapH(saHandler))

	// Federation Service
	federationServer := services.NewFederationServer(
		serviceProvider.FederationService(),
		opts.RepositoryProvider.UserRepository(connectCtx),
		opts.RepositoryProvider.UserFederatedIdentityRepository(connectCtx),
		opts.RepositoryProvider.IdPRepository(connectCtx),
		tokenService,
		opts.RepositoryProvider.SessionRepository(connectCtx),
		passwordHasher,
	)
	federationPath, federationHandler := ssov1connect.NewFederationServiceHandler(federationServer, interceptors)
	router.Any(federationPath+"*action", gin.WrapH(federationHandler))

	// User Attribute + User Attribute Mapper Service
	attrServer := services.NewUserAttributeServiceServer(
		opts.RepositoryProvider.UserAttributeRepository(connectCtx),
		opts.RepositoryProvider.UserAttributeMapperRepository(connectCtx),
	)
	attrPath, attrHandler := ssov1connect.NewUserAttributeServiceHandler(attrServer, interceptors)
	router.Any(attrPath+"*action", gin.WrapH(attrHandler))
	attrMapperPath, attrMapperHandler := ssov1connect.NewUserAttributeMapperServiceHandler(attrServer, interceptors)
	router.Any(attrMapperPath+"*action", gin.WrapH(attrMapperHandler))

	// Audit Service — read-only admin access to persisted audit events
	auditServer := services.NewAuditServer(repoProvider.AuditLogRepository(connectCtx))
	auditPath, auditHandler := ssov1connect.NewAuditServiceHandler(auditServer, interceptors)
	router.Any(auditPath+"*action", gin.WrapH(auditHandler))

	connectSpan.End()
	log.Info().Msg("Connect-RPC handlers registered successfully")
	// ---------- End Connect-RPC handlers ----------

	// --- GraphQL API wiring ---
	// Reuses the same cached repository instances as the REST/Connect-RPC APIs
	// above (via repoProvider) instead of constructing a second, independent
	// set — avoids duplicate index-creation calls and swallowed constructor
	// errors on every boot.
	if mongoRp, ok := repoProvider.(*mongodb.MongoRepositoryProvider); ok {
		gqlCtx, gqlSpan := telemetry.StartSpan(ctx, "shadow-sso", "NewSSOServer.graphql")
		defer gqlSpan.End()

		// Repos available via RepositoryProvider interface — reuse cached instances.
		userRepo := repoProvider.UserRepository(gqlCtx)
		clientRepo := repoProvider.ClientRepository(gqlCtx)
		sessionRepo := repoProvider.SessionRepository(gqlCtx)
		idpRepo := repoProvider.IdPRepository(gqlCtx)
		groupRepo := repoProvider.GroupRepository(gqlCtx)
		roleRepo := repoProvider.RoleRepository(gqlCtx)
		realmKeysRepo := repoProvider.RealmKeysRepository(gqlCtx)
		userAttrRepo := repoProvider.UserAttributeRepository(gqlCtx)
		userAttrMapperRepo := repoProvider.UserAttributeMapperRepository(gqlCtx)
		auditRepo := repoProvider.AuditLogRepository(gqlCtx)
		fedIDRepo := repoProvider.UserFederatedIdentityRepository(gqlCtx)

		// Repos not on the RepositoryProvider interface — use MongoRepositoryProvider directly.
		protocolMapperRepo := mongoRp.ProtocolMapperRepository(gqlCtx)
		authFlowRepo := mongoRp.AuthenticationFlowRepository(gqlCtx)
		clientScopeRepo := mongoRp.ClientScopeRepository(gqlCtx)
		realmSettingsRepo := mongoRp.RealmSettingsRepository(gqlCtx)

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
			AuditLogRepo:            auditRepo,
			FederatedIdentityRepo:   fedIDRepo,
		}

		graphqlHandler := graphql.AuthMiddleware(
			serviceProvider.TokenService(),
			bootstrapToken,
			graphql.NewHandler(resolver, "/graphql", graphql.GraphQLConfig{IsDevelopment: true}),
		)

		router.POST("/graphql", gin.WrapH(graphqlHandler))
		router.GET("/sandbox", gin.WrapH(graphql.SandboxHandler("/graphql")))
	}

	return router, nil
}

// seedRealmSettingsFromConfig persists realm settings derived from config on
// the first boot of a fresh MongoDB database. It is a no-op when a non-MongoDB
// repository provider is in use or when realm settings already exist, so
// admin-applied settings are never clobbered.
func seedRealmSettingsFromConfig(repoProvider services.RepositoryProvider, cfg *api.OpenIDProviderConfig) error {
	mongoRp, ok := repoProvider.(*mongodb.MongoRepositoryProvider)
	if !ok {
		return nil
	}

	ctx := context.Background()
	repo, ok := mongoRp.RealmSettingsRepository(ctx).(*mongodb.RealmSettingsRepository)
	if !ok {
		return nil
	}

	accessTokenLifespan := int(cfg.AccessTokenTTL.Seconds())
	if accessTokenLifespan <= 0 {
		accessTokenLifespan = 300
	}
	accessCodeLifespan := int(cfg.AuthCodeTTL.Seconds())
	if accessCodeLifespan <= 0 {
		accessCodeLifespan = 60
	}

	settings := &domain.RealmSettings{
		Realm:               "master",
		DisplayName:         "Shadow SSO",
		Enabled:             true,
		BruteForceProtected: true,
		SSLRequired:         "external",
		AccessTokenLifespan: accessTokenLifespan,
		AccessCodeLifespan:  accessCodeLifespan,
	}

	if _, err := repo.SeedRealmSettingsIfEmpty(ctx, settings); err != nil {
		return fmt.Errorf("failed to seed realm settings: %w", err)
	}
	return nil
}

// ensureBootstrapSSSOCTLClient idempotently creates the built-in public
// "sssoctl" OAuth client used by the ssoctl CLI device-code login flow. It is
// a no-op when the client already exists, so a customized client with that ID
// is never overwritten.
func ensureBootstrapSSSOCTLClient(ctx context.Context, clientRepo domain.ClientRepository, log zerolog.Logger) error {
	if _, err := clientRepo.GetClient(ctx, "sssoctl"); err != nil {
		if !errors.Is(err, domain.ErrClientNotFound) {
			return fmt.Errorf("failed to look up sssoctl client: %w", err)
		}
		client := &domain.Client{
			ID:                "sssoctl",
			Name:              "ssoctl CLI",
			Type:              domain.ClientTypePublic,
			IsActive:          true,
			IsConfidential:    false,
			TokenEndpointAuth: "none",
			AllowedGrantTypes: []string{"urn:ietf:params:oauth:grant-type:device_code", "refresh_token"},
			AllowedScopes:     []string{"openid", "profile", "email"},
			RequirePKCE:       false,
			RequireConsent:    false,
		}
		if err := clientRepo.CreateClient(ctx, client); err != nil {
			return fmt.Errorf("failed to create sssoctl client: %w", err)
		}
		log.Info().Str("client_id", "sssoctl").Msg("bootstrapped built-in sssoctl OAuth client")
		return nil
	}
	log.Debug().Str("client_id", "sssoctl").Msg("sssoctl OAuth client already exists, skipping bootstrap")
	return nil
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
