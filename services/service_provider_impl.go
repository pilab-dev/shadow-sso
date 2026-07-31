package services

import (
	"context"
	"errors"
	"fmt"

	"github.com/pilab-dev/shadow-sso/api"
	"github.com/pilab-dev/shadow-sso/apps/ssso/config"
	"github.com/pilab-dev/shadow-sso/cache"
	"github.com/pilab-dev/shadow-sso/domain"
	"github.com/pilab-dev/shadow-sso/internal/notifications"
	"github.com/pilab-dev/shadow-sso/internal/oidcflow"
	pkgauth "github.com/pilab-dev/shadow-sso/pkg/auth"
	"golang.org/x/crypto/bcrypt"
)

// DefaultServiceProvider implements the ServiceProvider interface.
type DefaultServiceProvider struct {
	repoProvider     RepositoryProvider
	config           *api.OpenIDProviderConfig
	appConfig        *config.Config
	tokenSigner      *TokenSigner
	tokenCache       cache.TokenStore
	flowStore        domain.FlowStore
	userSessionStore domain.UserSessionStore

	oauthService      OAuthService
	tokenService      TokenService
	pkceService       PKCEService
	jwksService       JWKSService
	clientService     ClientService
	federationService FederationService
	userService       UserService
	twoFactorService  TwoFactorService
	passwordHasher    domain.PasswordHasher

	smsService   domain.SMSService
	emailService domain.EmailService
	pushService  domain.PushNotificationService

	configurationService ConfigurationService

	phoneVerificationService PhoneVerificationService
	mfaService               MFAService
	pushMFAService           PushMFAService

	idpManagementService    IDPManagementService
	clientManagementService ClientManagementService
	serviceAccountService   ServiceAccountService
}

// DefaultServiceProviderOptions holds all necessary dependencies to create a DefaultServiceProvider.
type DefaultServiceProviderOptions struct {
	RepositoryProvider RepositoryProvider
	Config             *api.OpenIDProviderConfig
	AppConfig          *config.Config
	TokenSigner        *TokenSigner
	TokenCache         cache.TokenStore
	PkceRepository     domain.PkceRepository
	FlowStore          domain.FlowStore
	UserSessionStore   domain.UserSessionStore
	EncryptionKey      string
}

// NewDefaultServiceProvider creates a new instance of DefaultServiceProvider.
func NewDefaultServiceProvider(opts DefaultServiceProviderOptions) (*DefaultServiceProvider, error) {
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

	var configurationService ConfigurationService
	if opts.EncryptionKey != "" {
		configRepo := opts.RepositoryProvider.ConfigurationRepository(initCtx)
		var err error
		configurationService, err = newDefaultConfigurationService(configRepo, opts.EncryptionKey)
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
		pkceService:          newDefaultPKCEService(opts.PkceRepository),
		flowStore:            flowStore,
		userSessionStore:     userSessionStore,
		passwordHasher:       pkgauth.NewBcryptPasswordHasher(bcrypt.DefaultCost),
		configurationService: configurationService,
	}

	p.smsService = p.initializeSMSService(configurationService)
	p.emailService = p.initializeEmailService(configurationService)
	p.pushService = p.initializePushService(configurationService)

	return p, nil
}

var initCtx = context.Background()

func (p *DefaultServiceProvider) OAuthService() OAuthService {
	if p.oauthService == nil {
		p.oauthService = newDefaultOAuthService(
			p.repoProvider.TokenRepository(initCtx),
			p.repoProvider.AuthorizationCodeRepository(initCtx),
			p.repoProvider.DeviceAuthorizationRepository(initCtx),
			p.repoProvider.ClientRepository(initCtx),
			p.repoProvider.UserRepository(initCtx),
			p.repoProvider.SessionRepository(initCtx),
			p.TokenService(),
			p.config.Issuer,
		)
	}
	return p.oauthService
}

func (p *DefaultServiceProvider) TokenService() TokenService {
	if p.tokenService == nil {
		p.tokenService = newDefaultTokenService(
			p.repoProvider.TokenRepository(initCtx),
			p.tokenCache,
			p.config.Issuer,
			p.tokenSigner,
			p.repoProvider.PublicKeyRepository(initCtx),
			p.repoProvider.ServiceAccountRepository(initCtx),
			p.repoProvider.UserRepository(initCtx),
			p.repoProvider.GroupRepository(initCtx),
			p.repoProvider.RoleRepository(initCtx),
		)
	}
	return p.tokenService
}

func (p *DefaultServiceProvider) PKCEService() PKCEService {
	if p.pkceService == nil {
		panic("PKCEService was not initialized in NewDefaultServiceProvider")
	}
	return p.pkceService
}

func (p *DefaultServiceProvider) JWKSService() JWKSService {
	if p.jwksService == nil {
		// Use the actual signing key so JWKS serves the matching public key.
		if p.tokenSigner != nil && p.tokenSigner.HasRSASigner() {
			privKey := p.tokenSigner.GetRSAPrivateKey()
			p.jwksService = NewJWKSServiceWithKey(privKey, "rsa-default")
		} else {
			var err error
			p.jwksService, err = newDefaultJWKSService(p.config.KeyRotationPeriod)
			if err != nil {
				panic("failed to initialize JWKSService: " + err.Error())
			}
		}
	}
	return p.jwksService
}

func (p *DefaultServiceProvider) ClientService() ClientService {
	if p.clientService == nil {
		p.clientService = newClientService(p.repoProvider.ClientRepository(initCtx))
	}
	return p.clientService
}

func (p *DefaultServiceProvider) FederationService() FederationService {
	if p.federationService == nil {
		p.federationService = newFederationService(
			p.repoProvider.IdPRepository(initCtx),
			p.repoProvider.UserRepository(initCtx),
			p.repoProvider.UserFederatedIdentityRepository(initCtx),
			p.repoProvider.SessionRepository(initCtx),
			p.TokenService(),
			p.PasswordHasher(),
			p.config.Issuer+"/callback",
		)
	}
	return p.federationService
}

func (p *DefaultServiceProvider) PhoneVerificationService() PhoneVerificationService {
	if p.phoneVerificationService == nil {
		p.phoneVerificationService = domain.NewPhoneVerificationService(
			p.repoProvider.UserRepository(initCtx),
			p.smsService,
		)
	}
	return p.phoneVerificationService
}

func (p *DefaultServiceProvider) MFAService() MFAService {
	if p.mfaService == nil {
		pushSvc := domain.NewPushMFAService(
			p.repoProvider.UserRepository(initCtx),
			p.pushService,
		)
		p.pushMFAService = pushSvc
		p.mfaService = domain.NewMFAService(
			p.repoProvider.UserRepository(initCtx),
			p.emailService,
			pushSvc,
		)
	}
	return p.mfaService
}

func (p *DefaultServiceProvider) TwoFactorService() TwoFactorService {
	if p.twoFactorService == nil {
		p.twoFactorService = newTwoFactorService(
			p.repoProvider.UserRepository(initCtx),
			p.passwordHasher,
			p.MFAService(),
			p.PushMFAService(),
			"ShadowSSO",
		)
	}
	return p.twoFactorService
}

func (p *DefaultServiceProvider) UserService() UserService {
	if p.userService == nil {
		p.userService = newUserService(
			p.repoProvider.UserRepository(initCtx),
			p.PasswordHasher(),
			p.PhoneVerificationService(),
		)
	}
	return p.userService
}

func (p *DefaultServiceProvider) PasswordHasher() domain.PasswordHasher {
	if p.passwordHasher == nil {
		cost := bcrypt.DefaultCost
		if p.config.SecurityConfig.PasswordHashingCost > 0 {
			cost = p.config.SecurityConfig.PasswordHashingCost
		}
		p.passwordHasher = pkgauth.NewBcryptPasswordHasher(cost)
	}
	return p.passwordHasher
}

func (p *DefaultServiceProvider) FlowStore() domain.FlowStore {
	return p.flowStore
}

func (p *DefaultServiceProvider) UserSessionStore() domain.UserSessionStore {
	return p.userSessionStore
}

func (p *DefaultServiceProvider) PushMFAService() PushMFAService {
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

func (p *DefaultServiceProvider) ConfigurationService() ConfigurationService {
	return p.configurationService
}

func (p *DefaultServiceProvider) IDPManagementService() IDPManagementService {
	if p.idpManagementService == nil {
		p.idpManagementService = newIDPManagementService(p.repoProvider.IdPRepository(initCtx))
	}
	return p.idpManagementService
}

func (p *DefaultServiceProvider) ClientManagementService() ClientManagementService {
	if p.clientManagementService == nil {
		p.clientManagementService = newClientManagementService(p.repoProvider.ClientRepository(initCtx), p.PasswordHasher())
	}
	return p.clientManagementService
}

func (p *DefaultServiceProvider) ServiceAccountService() ServiceAccountService {
	if p.serviceAccountService == nil {
		p.serviceAccountService = newServiceAccountService(
			&defaultSAKeyGenerator{},
			p.repoProvider.ServiceAccountRepository(initCtx),
			p.repoProvider.PublicKeyRepository(initCtx),
		)
	}
	return p.serviceAccountService
}

func (p *DefaultServiceProvider) initializeSMSService(configService ConfigurationService) domain.SMSService {
	if configService == nil {
		if p.appConfig != nil {
			return notifications.NewTwilioSMSService(
				p.appConfig.TwilioAccountSID,
				p.appConfig.TwilioAuthToken,
				p.appConfig.TwilioPhoneNumber,
			)
		}
		return notifications.NewTwilioSMSService("", "", "")
	}

	accountSID := configService.GetStringWithDefault(initCtx, domain.ConfigTypeSMS, "account_sid", "")
	authToken := configService.GetStringWithDefault(initCtx, domain.ConfigTypeSMS, "auth_token", "")
	fromNumber := configService.GetStringWithDefault(initCtx, domain.ConfigTypeSMS, "phone_number", "")

	return notifications.NewTwilioSMSService(accountSID, authToken, fromNumber)
}

func (p *DefaultServiceProvider) initializeEmailService(configService ConfigurationService) domain.EmailService {
	if configService == nil {
		if p.appConfig != nil {
			return notifications.NewResendEmailService(
				p.appConfig.ResendAPIKey,
				p.appConfig.FromEmail,
				p.appConfig.NextPublicBaseURL,
			)
		}
		return notifications.NewResendEmailService("", "", "")
	}

	apiKey := configService.GetStringWithDefault(initCtx, domain.ConfigTypeEmail, "api_key", "")
	fromEmail := configService.GetStringWithDefault(initCtx, domain.ConfigTypeEmail, "from_email", "")
	baseURL := configService.GetStringWithDefault(initCtx, domain.ConfigTypeEmail, "base_url", "")

	return notifications.NewResendEmailService(apiKey, fromEmail, baseURL)
}

func (p *DefaultServiceProvider) initializePushService(configService ConfigurationService) domain.PushNotificationService {
	if configService == nil {
		if p.appConfig != nil {
			return notifications.NewFirebasePushService(
				p.appConfig.FirebaseProjectID,
				p.appConfig.FirebaseCredentialsPath,
			)
		}
		return notifications.NewFirebasePushService("", "")
	}

	projectID := configService.GetStringWithDefault(initCtx, domain.ConfigTypePush, "project_id", "")
	credentialsPath := configService.GetStringWithDefault(initCtx, domain.ConfigTypePush, "credentials_path", "")

	return notifications.NewFirebasePushService(projectID, credentialsPath)
}

var _ ServiceProvider = (*DefaultServiceProvider)(nil)
