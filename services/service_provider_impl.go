package services

import (
	"context" // Generally useful for service initialization context if needed
	"errors"
	"fmt"

	"github.com/pilab-dev/shadow-sso/api"
	"github.com/pilab-dev/shadow-sso/apps/ssso/config"
	"github.com/pilab-dev/shadow-sso/cache"
	"github.com/pilab-dev/shadow-sso/client"
	"github.com/pilab-dev/shadow-sso/domain" // Corrected: Single import of domain
	"github.com/pilab-dev/shadow-sso/internal/federation"
	"github.com/pilab-dev/shadow-sso/internal/notifications"
	"github.com/pilab-dev/shadow-sso/internal/oidcflow"
	pkgauth "github.com/pilab-dev/shadow-sso/pkg/auth"
	"golang.org/x/crypto/bcrypt" // For bcrypt.DefaultCost
)

// DefaultServiceProvider implements the ServiceProvider interface.
type DefaultServiceProvider struct {
	repoProvider RepositoryProvider
	config       *api.OpenIDProviderConfig // General app/OIDC config
	appConfig    *config.Config            // Viper configuration
	tokenSigner  *TokenSigner
	tokenCache   cache.TokenStore
	// For OIDC flows, these are now interface-based.
	flowStore        domain.FlowStore
	userSessionStore domain.UserSessionStore

	// Cached services to ensure singletons where appropriate
	oauthService      *OAuthService
	tokenService      *TokenService
	pkceService       *PKCEService
	jwksService       *JWKSService
	clientService     *client.ClientService
	federationService *federation.Service
	userService       *UserServer
	twoFactorService  *TwoFactorServer
	passwordHasher    domain.PasswordHasher // Corrected: use domain.PasswordHasher

	// Infrastructure services
	smsService   domain.SMSService
	emailService domain.EmailService
	pushService  domain.PushNotificationService

	// Configuration service for operational settings
	configurationService *ConfigurationService

	// Domain services
	phoneVerificationService *domain.PhoneVerificationService
	mfaService               *domain.MFAService
	pushMFAService           *domain.PushMFAService
}

// DefaultServiceProviderOptions holds all necessary dependencies to create a DefaultServiceProvider.
type DefaultServiceProviderOptions struct {
	RepositoryProvider RepositoryProvider
	Config             *api.OpenIDProviderConfig
	AppConfig          *config.Config // Viper configuration
	TokenSigner        *TokenSigner
	TokenCache         cache.TokenStore
	PkceRepository     domain.PkceRepository   // Explicit PKCE repository
	FlowStore          domain.FlowStore        // Optional: if not provided, can be initialized internally
	UserSessionStore   domain.UserSessionStore // Optional: if not provided, can be initialized internally
	EncryptionKey      string                  // 32-byte key for configuration encryption
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
		return nil, errors.New("PkceRepository is required in DefaultServiceProviderOptions")
	}

	// Initialize configuration service
	var configurationService *ConfigurationService
	if opts.EncryptionKey != "" {
		configRepo := opts.RepositoryProvider.ConfigurationRepository(initCtx)
		var err error
		configurationService, err = NewConfigurationService(configRepo, opts.EncryptionKey)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize configuration service: %w", err)
		}
	}

	p := &DefaultServiceProvider{
		repoProvider:         opts.RepositoryProvider,
		config:               opts.Config,
		appConfig:            opts.AppConfig,
		tokenSigner:          opts.TokenSigner,
		tokenCache:           opts.TokenCache,
		pkceService:          NewPKCEService(opts.PkceRepository), // Initialize PKCEService directly
		flowStore:            flowStore,
		userSessionStore:     userSessionStore,
		passwordHasher:       pkgauth.NewBcryptPasswordHasher(bcrypt.DefaultCost),
		configurationService: configurationService,

		// pkceRepo field is not needed if service is initialized directly
	}

	// Initialize infrastructure services
	p.smsService = p.initializeSMSService(configurationService)
	p.emailService = p.initializeEmailService(configurationService)
	p.pushService = p.initializePushService(configurationService)

	return p, nil
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

func (p *DefaultServiceProvider) PhoneVerificationService() *domain.PhoneVerificationService {
	if p.phoneVerificationService == nil {
		p.phoneVerificationService = domain.NewPhoneVerificationService(
			p.repoProvider.UserRepository(initCtx),
			p.smsService,
		)
	}
	return p.phoneVerificationService
}

func (p *DefaultServiceProvider) MFAService() *domain.MFAService {
	if p.mfaService == nil {
		p.mfaService = domain.NewMFAService(
			p.repoProvider.UserRepository(initCtx),
			p.emailService,
			p.PushMFAService(), // Include PushMFAService
		)
	}
	return p.mfaService
}

func (p *DefaultServiceProvider) TwoFactorService() *TwoFactorServer {
	if p.twoFactorService == nil {
		p.twoFactorService = NewTwoFactorServer(
			p.repoProvider.UserRepository(initCtx),
			p.passwordHasher,
			p.MFAService(),     // Get MFAService via its getter to ensure it's initialized
			p.PushMFAService(), // Get PushMFAService via its getter to ensure it's initialized
			"ShadowSSO",        // App name for TOTP/HOTP issuer
		)
	}
	return p.twoFactorService
}

func (p *DefaultServiceProvider) UserService() *UserServer {
	if p.userService == nil {
		p.userService = NewUserServer(
			p.repoProvider.UserRepository(initCtx),
			p.PasswordHasher(),
			p.PhoneVerificationService(),
		)
	}
	return p.userService
}

func (p *DefaultServiceProvider) PasswordHasher() domain.PasswordHasher {
	if p.passwordHasher == nil {
		// Using bcrypt as the default. Cost can be from config.
		cost := bcrypt.DefaultCost
		if p.config.SecurityConfig.PasswordHashingCost > 0 {
			cost = p.config.SecurityConfig.PasswordHashingCost
		}
		p.passwordHasher = pkgauth.NewBcryptPasswordHasher(cost)
	}
	return p.passwordHasher
}

func (p *DefaultServiceProvider) FlowStore() domain.FlowStore {
	// Already initialized in NewDefaultServiceProvider, just return it.
	return p.flowStore
}

func (p *DefaultServiceProvider) UserSessionStore() domain.UserSessionStore {
	// Already initialized in NewDefaultServiceProvider.
	return p.userSessionStore
}

func (p *DefaultServiceProvider) PushMFAService() *domain.PushMFAService {
	if p.pushMFAService == nil {
		p.pushMFAService = domain.NewPushMFAService(
			p.repoProvider.UserRepository(initCtx),
			p.pushService,
		)
	}
	return p.pushMFAService
}

func (p *DefaultServiceProvider) PushNotificationService() domain.PushNotificationService {
	return p.pushService
}

func (p *DefaultServiceProvider) ConfigurationService() *ConfigurationService {
	return p.configurationService
}

// initializeSMSService initializes the SMS service with configuration
func (p *DefaultServiceProvider) initializeSMSService(configService *ConfigurationService) domain.SMSService {
	if configService == nil {
		// Use viper config if configuration service is not available
		if p.appConfig != nil {
			return notifications.NewTwilioSMSService(
				p.appConfig.TwilioAccountSID,
				p.appConfig.TwilioAuthToken,
				p.appConfig.TwilioPhoneNumber,
			)
		}
		// Fallback to empty config if neither configuration service nor app config is available
		return notifications.NewTwilioSMSService("", "", "")
	}

	accountSID := configService.GetStringWithDefault(initCtx, domain.ConfigTypeSMS, "account_sid", "")
	authToken := configService.GetStringWithDefault(initCtx, domain.ConfigTypeSMS, "auth_token", "")
	fromNumber := configService.GetStringWithDefault(initCtx, domain.ConfigTypeSMS, "phone_number", "")

	return notifications.NewTwilioSMSService(accountSID, authToken, fromNumber)
}

// initializeEmailService initializes the email service with configuration
func (p *DefaultServiceProvider) initializeEmailService(configService *ConfigurationService) domain.EmailService {
	if configService == nil {
		// Use viper config if configuration service is not available
		if p.appConfig != nil {
			return notifications.NewResendEmailService(
				p.appConfig.ResendAPIKey,
				p.appConfig.FromEmail,
				p.appConfig.NextPublicBaseURL,
			)
		}
		// Fallback to empty config if neither configuration service nor app config is available
		return notifications.NewResendEmailService("", "", "")
	}

	apiKey := configService.GetStringWithDefault(initCtx, domain.ConfigTypeEmail, "api_key", "")
	fromEmail := configService.GetStringWithDefault(initCtx, domain.ConfigTypeEmail, "from_email", "")
	baseURL := configService.GetStringWithDefault(initCtx, domain.ConfigTypeEmail, "base_url", "")

	return notifications.NewResendEmailService(apiKey, fromEmail, baseURL)
}

// initializePushService initializes the push notification service with configuration
func (p *DefaultServiceProvider) initializePushService(configService *ConfigurationService) domain.PushNotificationService {
	if configService == nil {
		// Use viper config if configuration service is not available
		if p.appConfig != nil {
			return notifications.NewFirebasePushService(
				p.appConfig.FirebaseProjectID,
				p.appConfig.FirebaseCredentialsPath,
			)
		}
		// Fallback to empty config if neither configuration service nor app config is available
		return notifications.NewFirebasePushService("", "")
	}

	projectID := configService.GetStringWithDefault(initCtx, domain.ConfigTypePush, "project_id", "")
	credentialsPath := configService.GetStringWithDefault(initCtx, domain.ConfigTypePush, "credentials_path", "")

	return notifications.NewFirebasePushService(projectID, credentialsPath)
}

// Compile-time check
var _ ServiceProvider = (*DefaultServiceProvider)(nil)
