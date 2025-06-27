package services

import (
	"context" // Generally useful for service initialization context if needed
	"errors"

	ssso "github.com/pilab-dev/shadow-sso"
	"github.com/pilab-dev/shadow-sso/cache"
	"github.com/pilab-dev/shadow-sso/client"
	"github.com/pilab-dev/shadow-sso/domain"
	"github.com/pilab-dev/shadow-sso/internal/auth" // For BcryptPasswordHasher
	"github.com/pilab-dev/shadow-sso/internal/federation"
	"github.com/pilab-dev/shadow-sso/internal/oidcflow"
	"golang.org/x/crypto/bcrypt" // For bcrypt.DefaultCost
)

// DefaultServiceProvider implements the ServiceProvider interface.
type DefaultServiceProvider struct {
	repoProvider RepositoryProvider
	config       *ssso.OpenIDProviderConfig // General app/OIDC config
	tokenSigner  *TokenSigner
	tokenCache   cache.TokenStore
	// For OIDC flows, these are currently in-memory.
	// If they become interface-based and provided by RepositoryProvider, adjust accordingly.
	flowStore        *oidcflow.InMemoryFlowStore
	userSessionStore *oidcflow.InMemoryUserSessionStore

	// Cached services to ensure singletons where appropriate
	oauthService      *OAuthService
	tokenService      *TokenService
	pkceService       *PKCEService
	jwksService       *JWKSService
	clientService     *client.ClientService
	federationService *federation.Service
	passwordHasher    PasswordHasher
}

// DefaultServiceProviderOptions holds all necessary dependencies to create a DefaultServiceProvider.
type DefaultServiceProviderOptions struct {
	RepositoryProvider RepositoryProvider
	Config             *ssso.OpenIDProviderConfig
	TokenSigner        *TokenSigner
	TokenCache         cache.TokenStore
	PkceRepository     domain.PkceRepository              // Explicit PKCE repository
	FlowStore          *oidcflow.InMemoryFlowStore        // Optional: if not provided, can be initialized internally
	UserSessionStore   *oidcflow.InMemoryUserSessionStore // Optional: if not provided, can be initialized internally
}

// NewDefaultServiceProvider creates a new instance of DefaultServiceProvider.
func NewDefaultServiceProvider(opts DefaultServiceProviderOptions) (*DefaultServiceProvider, error) {
	// Initialize stores if not provided
	flowStore := opts.FlowStore
	if flowStore == nil {
		flowStore = oidcflow.NewInMemoryFlowStore()
	}
	userSessionStore := opts.UserSessionStore
	if userSessionStore == nil {
		userSessionStore = oidcflow.NewInMemoryUserSessionStore()
	}

	if opts.PkceRepository == nil {
		// PKCE is fundamental for OAuth2, so we should fail fast if no implementation is provided.
		// Alternatively, could try to get from opts.RepositoryProvider.PkceRepository(initCtx)
		// but making it explicit in options is cleaner.
		return nil, errors.New("PkceRepository is required in DefaultServiceProviderOptions")
	}

	return &DefaultServiceProvider{
		repoProvider:     opts.RepositoryProvider,
		config:           opts.Config,
		tokenSigner:      opts.TokenSigner,
		tokenCache:       opts.TokenCache,
		pkceService:      NewPKCEService(opts.PkceRepository), // Initialize PKCEService directly
		flowStore:        flowStore,
		userSessionStore: userSessionStore,
		// pkceRepo field is not needed if service is initialized directly
	}, nil
}

// Context used for repository getters. For singleton services, this is typically context.Background().
var initCtx = context.Background()

func (p *DefaultServiceProvider) OAuthService() *OAuthService {
	if p.oauthService == nil {
		// Special case for ClientRepository [client.ClientStore] implementation

		// OAuthService dependencies:
		// tokenRepo, authCodeRepo, deviceAuthRepo, clientRepo, userRepo, sessionRepo, tokenService, issuer
		p.oauthService = NewOAuthService(
			p.repoProvider.TokenRepository(initCtx),
			p.repoProvider.AuthorizationCodeRepository(initCtx),
			p.repoProvider.DeviceAuthorizationRepository(initCtx),
			p.repoProvider.ClientRepository(initCtx),
			p.repoProvider.UserRepository(initCtx),
			p.repoProvider.SessionRepository(initCtx),
			p.TokenService(), // Get TokenService via its getter to ensure it's initialized
			p.config.Issuer,
		)
	}
	return p.oauthService
}

func (p *DefaultServiceProvider) TokenService() *TokenService {
	if p.tokenService == nil {
		// TokenService dependencies:
		// repo, cache, issuer, signer, pubKeyRepo, saRepo, userRepo
		p.tokenService = NewTokenService(
			p.repoProvider.TokenRepository(initCtx),
			p.tokenCache, // Direct from options
			p.config.Issuer,
			p.tokenSigner, // Direct from options
			p.repoProvider.PublicKeyRepository(initCtx),
			p.repoProvider.ServiceAccountRepository(initCtx),
			p.repoProvider.UserRepository(initCtx),
		)
	}
	return p.tokenService
}

func (p *DefaultServiceProvider) PKCEService() *PKCEService {
	// PKCEService is now initialized in NewDefaultServiceProvider using the explicit PkceRepository from options.
	if p.pkceService == nil {
		// This should not happen if NewDefaultServiceProvider ensures it.
		// However, as a safeguard or if initialization logic changes:
		panic("PKCEService was not initialized in NewDefaultServiceProvider")
	}
	return p.pkceService
}

func (p *DefaultServiceProvider) JWKSService() *JWKSService {
	if p.jwksService == nil {
		// JWKSService dependency: privateKey (from config or key management)
		// Assuming TokenSigner holds the key or can provide it.
		// This might need adjustment based on how JWKS keys are sourced.
		// For now, assuming NewJWKSService can be initialized, possibly using keys from TokenSigner.
		// The current NewJWKSService takes a rotationInterval and generates keys.
		// It doesn't directly take external keys for serving but manages its own.
		var err error
		p.jwksService, err = NewJWKSService(p.config.KeyRotationPeriod) // Default from config
		if err != nil {
			panic("failed to initialize JWKSService: " + err.Error())
		}
		// If JWKSService needs to reflect keys from TokenSigner, it needs a way to access them.
		// e.g., p.jwksService.AddKeyProvider(p.tokenSigner.GetKeyProvider())
		// For now, the existing NewJWKSService creates its own keys.
	}
	return p.jwksService
}

func (p *DefaultServiceProvider) ClientService() *client.ClientService {
	if p.clientService == nil {
		p.clientService = client.NewClientService(p.repoProvider.ClientRepository(initCtx))
	}
	return p.clientService
}

func (p *DefaultServiceProvider) FederationService() *federation.Service {
	if p.federationService == nil {
		// FederationService dependencies: idpRepo, userRepo, fedIdRepo, clientService, tokenService, config
		// The NewService in internal/federation takes: IdPRepository, UserRepository, UserFederatedIdentityRepository, *client.ClientService, *TokenService, string (issuerURL), string (callbackBaseURL)
		// callbackBaseURL needs to be constructed or taken from config.
		callbackBaseURL := p.config.Issuer // Assuming issuer is the base for /federation/callback
		if callbackBaseURL == "" {
			// Attempt to construct from a configured base URL if Issuer is not suitable for callbacks
			// For example, if Issuer is just an identifier, not a URL.
			// This might require another field in OpenIDProviderConfig like "ExternalBaseURL"
			// For now, using Issuer and logging a warning if it seems problematic.
			// log.Warn().Msg("FederationService callback base URL derived from Issuer. Ensure this is correct.")
		}

		p.federationService = federation.NewService(
			p.repoProvider.IdPRepository(initCtx),
			"https://sso.pilab.hu/oauth2/federeation/callback", // Pass full config for provider-specific details if needed by NewService
		)
	}
	return p.federationService
}

func (p *DefaultServiceProvider) PasswordHasher() PasswordHasher {
	if p.passwordHasher == nil {
		// Using bcrypt as the default. Cost can be from config.
		cost := bcrypt.DefaultCost
		if p.config.SecurityConfig.PasswordHashingCost > 0 {
			cost = p.config.SecurityConfig.PasswordHashingCost
		}
		p.passwordHasher = auth.NewBcryptPasswordHasher(cost)
	}
	return p.passwordHasher
}

func (p *DefaultServiceProvider) FlowStore() *oidcflow.InMemoryFlowStore {
	// Already initialized in NewDefaultServiceProvider, just return it.
	// If it were interface-based and from repoProvider, the pattern would be similar to other services.
	return p.flowStore
}

func (p *DefaultServiceProvider) UserSessionStore() *oidcflow.InMemoryUserSessionStore {
	// Already initialized in NewDefaultServiceProvider.
	return p.userSessionStore
}

// Compile-time check
var _ ServiceProvider = (*DefaultServiceProvider)(nil)
