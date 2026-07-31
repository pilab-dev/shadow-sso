package services_test

import (
	"context"
	"testing"
	"time"

	ssso "github.com/pilab-dev/shadow-sso"
	"github.com/pilab-dev/shadow-sso/api"
	"github.com/pilab-dev/shadow-sso/apps/ssso/config"
	mock_cache "github.com/pilab-dev/shadow-sso/cache/mocks"
	"github.com/pilab-dev/shadow-sso/domain"
	mock_domain "github.com/pilab-dev/shadow-sso/domain/mocks"
	"github.com/pilab-dev/shadow-sso/services"
	mock_services "github.com/pilab-dev/shadow-sso/services/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func TestNewDefaultServiceProvider_Success(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockRepoProvider := mock_services.NewMockRepositoryProvider(ctrl)
	mockTokenSigner := services.NewTokenSigner() // Use actual simple signer
	mockTokenCache := mock_cache.NewMockTokenStore(ctrl)
	mockPkceRepo := mock_domain.NewMockPkceRepository(ctrl)
	appConfig := &api.OpenIDProviderConfig{Issuer: "http://issuer.com"}
	mockAppConfig := &config.Config{} // Simple empty config for testing

	setupMockRepoProviderForServiceGetters(mockRepoProvider, ctrl)

	opts := services.DefaultServiceProviderOptions{
		RepositoryProvider: mockRepoProvider,
		Config:             appConfig,
		AppConfig:          mockAppConfig,
		TokenSigner:        mockTokenSigner,
		TokenCache:         mockTokenCache,
		PkceRepository:     mockPkceRepo,
		FlowStore:          ssso.NewInMemoryFlowStore(),
		UserSessionStore:   ssso.NewInMemoryUserSessionStore(),
	}

	sp, err := services.NewDefaultServiceProvider(opts)
	require.NoError(t, err)
	require.NotNil(t, sp)

	// Test that stores are initialized if they were nil in opts
	optsNoStores := services.DefaultServiceProviderOptions{
		RepositoryProvider: mockRepoProvider,
		Config:             appConfig,
		AppConfig:          mockAppConfig,
		TokenSigner:        mockTokenSigner,
		TokenCache:         mockTokenCache,
		PkceRepository:     mockPkceRepo,
		// FlowStore and UserSessionStore are nil
	}
	spNoStores, err := services.NewDefaultServiceProvider(optsNoStores)
	require.NoError(t, err)
	require.NotNil(t, spNoStores)
	assert.NotNil(t, spNoStores.FlowStore(), "FlowStore should be initialized by NewDefaultServiceProvider if nil")
	assert.NotNil(t, spNoStores.UserSessionStore(), "UserSessionStore should be initialized by NewDefaultServiceProvider if nil")
}

func TestNewDefaultServiceProvider_Error_MissingPkceRepository(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockRepoProvider := mock_services.NewMockRepositoryProvider(ctrl)
	mockTokenSigner := services.NewTokenSigner()
	mockTokenCache := mock_cache.NewMockTokenStore(ctrl)
	// mockPkceRepo is deliberately omitted / nil
	appConfig := &api.OpenIDProviderConfig{}
	mockAppConfig := &config.Config{}

	setupMockRepoProviderForServiceGetters(mockRepoProvider, ctrl)

	opts := services.DefaultServiceProviderOptions{
		RepositoryProvider: mockRepoProvider,
		Config:             appConfig,
		AppConfig:          mockAppConfig,
		TokenSigner:        mockTokenSigner,
		TokenCache:         mockTokenCache,
		PkceRepository:     nil, // Explicitly nil
	}

	sp, err := services.NewDefaultServiceProvider(opts)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "PkceRepository is required")
	require.Nil(t, sp)
}

// Test individual service getters: OAuthService, TokenService, etc.
// This is a helper function to set up mocks for repository getters.
func setupMockRepoProviderForServiceGetters(mockRepoProvider *mock_services.MockRepositoryProvider, ctrl *gomock.Controller) {
	// Setup default expectations for all repository getters used by services
	// These can be .AnyTimes() if the exact number of calls isn't critical for these tests,
	// or specific if testing singleton behavior carefully.
	mockRepoProvider.EXPECT().UserRepository(gomock.Any()).Return(mock_domain.NewMockUserRepository(ctrl)).AnyTimes()
	mockRepoProvider.EXPECT().SessionRepository(gomock.Any()).Return(mock_domain.NewMockSessionRepository(ctrl)).AnyTimes()
	mockRepoProvider.EXPECT().UserFederatedIdentityRepository(gomock.Any()).Return(mock_domain.NewMockUserFederatedIdentityRepository(ctrl)).AnyTimes()
	mockRepoProvider.EXPECT().TokenRepository(gomock.Any()).Return(mock_domain.NewMockTokenRepository(ctrl)).AnyTimes()
	mockRepoProvider.EXPECT().AuthorizationCodeRepository(gomock.Any()).Return(mock_domain.NewMockAuthorizationCodeRepository(ctrl)).AnyTimes()
	// PkceRepository is passed explicitly, not typically fetched from general repo provider by DefaultServiceProvider itself for PKCEService
	// mockRepoProvider.EXPECT().PkceRepository(gomock.Any()).Return(mock_domain.NewMockPkceRepository(ctrl)).AnyTimes()
	mockRepoProvider.EXPECT().DeviceAuthorizationRepository(gomock.Any()).Return(mock_domain.NewMockDeviceAuthorizationRepository(ctrl)).AnyTimes()
	mockRepoProvider.EXPECT().ClientRepository(gomock.Any()).Return(mock_domain.NewMockClientRepository(ctrl)).AnyTimes()
	mockRepoProvider.EXPECT().PublicKeyRepository(gomock.Any()).Return(mock_domain.NewMockPublicKeyRepository(ctrl)).AnyTimes()
	mockRepoProvider.EXPECT().ServiceAccountRepository(gomock.Any()).Return(mock_domain.NewMockServiceAccountRepository(ctrl)).AnyTimes()
	mockRepoProvider.EXPECT().IdPRepository(gomock.Any()).Return(mock_domain.NewMockIdPRepository(ctrl)).AnyTimes()
	mockRepoProvider.EXPECT().GroupRepository(gomock.Any()).Return(mock_domain.NewMockGroupRepository(ctrl)).AnyTimes()
	mockRepoProvider.EXPECT().RoleRepository(gomock.Any()).Return(mock_domain.NewMockRoleRepository(ctrl)).AnyTimes()
	// mockRepoProvider.EXPECT().ConfigurationRepository(gomock.Any()).Return(mock_domain.NewMockConfigurationRepository(ctrl)).AnyTimes() // Commented out for tests that need specific config repo
}

func TestDefaultServiceProvider_Getters(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockRepoProvider := mock_services.NewMockRepositoryProvider(ctrl)
	mockTokenSigner := services.NewTokenSigner()
	mockTokenCache := mock_cache.NewMockTokenStore(ctrl)
	mockPkceRepo := mock_domain.NewMockPkceRepository(ctrl)
	appConfig := &api.OpenIDProviderConfig{
		Issuer:            "http://issuer.com",
		KeyRotationPeriod: time.Hour,
		SecurityConfig:    api.SecurityConfig{PasswordHashingCost: 10},
		// TOTPIssuerName:    "TestSSO",
	}
	mockAppConfig := &config.Config{}

	setupMockRepoProviderForServiceGetters(mockRepoProvider, ctrl)

	opts := services.DefaultServiceProviderOptions{
		RepositoryProvider: mockRepoProvider,
		Config:             appConfig,
		AppConfig:          mockAppConfig,
		TokenSigner:        mockTokenSigner,
		TokenCache:         mockTokenCache,
		PkceRepository:     mockPkceRepo,
	}
	sp, err := services.NewDefaultServiceProvider(opts)
	require.NoError(t, err)
	require.NotNil(t, sp)

	// Test each getter
	// For each service, check it's not nil and that it's a singleton

	// OAuthService
	oauthService1 := sp.OAuthService()
	assert.NotNil(t, oauthService1)
	oauthService2 := sp.OAuthService()
	assert.Same(t, oauthService1, oauthService2, "OAuthService should be a singleton")

	// TokenService
	tokenService1 := sp.TokenService()
	assert.NotNil(t, tokenService1)
	tokenService2 := sp.TokenService()
	assert.Same(t, tokenService1, tokenService2, "TokenService should be a singleton")

	// PKCEService
	pkceService1 := sp.PKCEService()
	assert.NotNil(t, pkceService1)
	pkceService2 := sp.PKCEService()
	assert.Same(t, pkceService1, pkceService2, "PKCEService should be a singleton")

	// JWKSService
	jwksService1 := sp.JWKSService()
	assert.NotNil(t, jwksService1)
	jwksService2 := sp.JWKSService()
	assert.Same(t, jwksService1, jwksService2, "JWKSService should be a singleton")

	// ClientService
	clientService1 := sp.ClientService()
	assert.NotNil(t, clientService1)
	clientService2 := sp.ClientService()
	assert.Same(t, clientService1, clientService2, "ClientService should be a singleton")

	// FederationService
	fedService1 := sp.FederationService()
	assert.NotNil(t, fedService1)
	fedService2 := sp.FederationService()
	assert.Same(t, fedService1, fedService2, "FederationService should be a singleton")

	// PasswordHasher
	hasher1 := sp.PasswordHasher()
	assert.NotNil(t, hasher1)
	hasher2 := sp.PasswordHasher()
	assert.Same(t, hasher1, hasher2, "PasswordHasher should be a singleton")

	// FlowStore
	flowStore1 := sp.FlowStore()
	assert.NotNil(t, flowStore1)
	flowStore2 := sp.FlowStore()
	assert.Same(t, flowStore1, flowStore2, "FlowStore should be a singleton")

	// UserSessionStore
	userSessionStore1 := sp.UserSessionStore()
	assert.NotNil(t, userSessionStore1)
	userSessionStore2 := sp.UserSessionStore()
	assert.Same(t, userSessionStore1, userSessionStore2, "UserSessionStore should be a singleton")

	// PhoneVerificationService
	phoneVerificationService1 := sp.PhoneVerificationService()
	assert.NotNil(t, phoneVerificationService1)
	phoneVerificationService2 := sp.PhoneVerificationService()
	assert.Same(t, phoneVerificationService1, phoneVerificationService2, "PhoneVerificationService should be a singleton")

	// MFAService
	mfaService1 := sp.MFAService()
	assert.NotNil(t, mfaService1)
	mfaService2 := sp.MFAService()
	assert.Same(t, mfaService1, mfaService2, "MFAService should be a singleton")

	// PushMFAService
	pushMFAService1 := sp.PushMFAService()
	assert.NotNil(t, pushMFAService1)
	pushMFAService2 := sp.PushMFAService()
	assert.Same(t, pushMFAService1, pushMFAService2, "PushMFAService should be a singleton")

	// UserService
	userService1 := sp.UserService()
	assert.NotNil(t, userService1)
	userService2 := sp.UserService()
	assert.Same(t, userService1, userService2, "UserService should be a singleton")

	// TwoFactorService
	twoFactorService1 := sp.TwoFactorService()
	assert.NotNil(t, twoFactorService1)
	twoFactorService2 := sp.TwoFactorService()
	assert.Same(t, twoFactorService1, twoFactorService2, "TwoFactorService should be a singleton")

	// PushNotificationService
	pushNotificationService1 := sp.PushNotificationService()
	assert.NotNil(t, pushNotificationService1)
	pushNotificationService2 := sp.PushNotificationService()
	assert.Same(t, pushNotificationService1, pushNotificationService2, "PushNotificationService should be a singleton")
}

// TODO: Add tests for JWKSService initialization if it involves complex key loading logic
// that depends on TokenSigner or other external factors not covered by its own unit tests.
// Current JWKSService NewJWKSService just takes rotationInterval and generates keys internally.

// TODO: Add tests for FederationService if its initialization logic from config is complex
// e.g. callback URL construction nuances. Current DefaultServiceProvider uses Issuer URL.
// The NewService in internal/federation takes issuerURL and callbackBaseURL.
// DefaultServiceProvider passes config.Issuer for both if not distinguished.
// This test ensures it's constructed; specific behavior of FederationService is for its own tests.

// Note: Mocking for domain.RepositoryProvider getters uses .AnyTimes() because the exact order
// or number of calls to these getters (e.g. UserRepository) isn't the primary focus of testing
// the ServiceProvider's own logic (which is mostly about construction and singleton management).
// What's important is that when a service like UserService is requested, the ServiceProvider
// correctly calls `repoProvider.UserRepository()` to get the dependency for `NewUserService`.
// The actual interaction with the methods of the returned UserRepository (e.g. GetUserByEmail)
// would be tested in UserService_test.go or handler tests that use UserService.
// Here, we just ensure the plumbing of ServiceProvider is correct.
// If a service getter in DefaultServiceProvider had complex logic based on multiple repo calls,
// then more specific expectations on the mockRepoProvider might be needed for that getter's test.
// For simple pass-through to New...Service(repoProvider.GetRepoX(), ...), .AnyTimes() is fine.
// The mock repositories (e.g. mock_domain.NewMockUserRepository(ctrl)) themselves are just stubs here.
// Their methods are not expected to be called by *these* ServiceProvider tests.
// They would be called if we were testing a service that *uses* these mock repos.
// This setup is primarily for testing the construction and singleton nature of services from the provider.
// The mock_domain.MockRepositoryProvider is the key mock here.
// The mock_domain.NewMock...Repository(ctrl) calls are just to satisfy the return types of the
// RepositoryProvider interface methods.

// One specific point: PkceRepository is explicitly passed in DefaultServiceProviderOptions.
// The mockRepoProvider.EXPECT().PkceRepository(...) is commented out because DefaultServiceProvider
// does *not* call its repoProvider's PkceRepository() method; it uses the one from options.
// If it *did* try to get PkceRepo from the general repoProvider, that mock expectation would be needed.
// This confirms the design choice of explicit PkceRepo dependency.

func TestDefaultServiceProvider_InitializeSMSService_WithAppConfig(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockRepoProvider := mock_services.NewMockRepositoryProvider(ctrl)
	mockTokenSigner := services.NewTokenSigner()
	mockTokenCache := mock_cache.NewMockTokenStore(ctrl)
	mockPkceRepo := mock_domain.NewMockPkceRepository(ctrl)
	appConfig := &api.OpenIDProviderConfig{Issuer: "http://issuer.com"}
	mockAppConfig := &config.Config{
		TwilioAccountSID:  "test-sid",
		TwilioAuthToken:   "test-token",
		TwilioPhoneNumber: "+1234567890",
	}

	setupMockRepoProviderForServiceGetters(mockRepoProvider, ctrl)

	opts := services.DefaultServiceProviderOptions{
		RepositoryProvider: mockRepoProvider,
		Config:             appConfig,
		AppConfig:          mockAppConfig,
		TokenSigner:        mockTokenSigner,
		TokenCache:         mockTokenCache,
		PkceRepository:     mockPkceRepo,
	}

	sp, err := services.NewDefaultServiceProvider(opts)
	require.NoError(t, err)
	require.NotNil(t, sp)

	// SMS service should be initialized with app config values
	smsService := sp.PushNotificationService() // This tests that services are initialized
	assert.NotNil(t, smsService)
}

func TestDefaultServiceProvider_InitializeEmailService_WithAppConfig(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockRepoProvider := mock_services.NewMockRepositoryProvider(ctrl)
	mockTokenSigner := services.NewTokenSigner()
	mockTokenCache := mock_cache.NewMockTokenStore(ctrl)
	mockPkceRepo := mock_domain.NewMockPkceRepository(ctrl)
	appConfig := &api.OpenIDProviderConfig{Issuer: "http://issuer.com"}
	mockAppConfig := &config.Config{
		ResendAPIKey:      "test-api-key",
		FromEmail:         "test@example.com",
		NextPublicBaseURL: "https://example.com",
	}

	setupMockRepoProviderForServiceGetters(mockRepoProvider, ctrl)

	opts := services.DefaultServiceProviderOptions{
		RepositoryProvider: mockRepoProvider,
		Config:             appConfig,
		AppConfig:          mockAppConfig,
		TokenSigner:        mockTokenSigner,
		TokenCache:         mockTokenCache,
		PkceRepository:     mockPkceRepo,
	}

	sp, err := services.NewDefaultServiceProvider(opts)
	require.NoError(t, err)
	require.NotNil(t, sp)

	// Email service should be initialized
	emailService := sp.PushNotificationService() // This tests that services are initialized
	assert.NotNil(t, emailService)
}

func TestDefaultServiceProvider_InitializePushService_WithAppConfig(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockRepoProvider := mock_services.NewMockRepositoryProvider(ctrl)
	mockTokenSigner := services.NewTokenSigner()
	mockTokenCache := mock_cache.NewMockTokenStore(ctrl)
	mockPkceRepo := mock_domain.NewMockPkceRepository(ctrl)
	appConfig := &api.OpenIDProviderConfig{Issuer: "http://issuer.com"}
	mockAppConfig := &config.Config{
		FirebaseProjectID:       "test-project",
		FirebaseCredentialsPath: "/path/to/credentials.json",
	}

	setupMockRepoProviderForServiceGetters(mockRepoProvider, ctrl)

	opts := services.DefaultServiceProviderOptions{
		RepositoryProvider: mockRepoProvider,
		Config:             appConfig,
		AppConfig:          mockAppConfig,
		TokenSigner:        mockTokenSigner,
		TokenCache:         mockTokenCache,
		PkceRepository:     mockPkceRepo,
	}

	sp, err := services.NewDefaultServiceProvider(opts)
	require.NoError(t, err)
	require.NotNil(t, sp)

	// Push service should be initialized
	pushService := sp.PushNotificationService()
	assert.NotNil(t, pushService)
}

func TestDefaultServiceProvider_InitializeServices_WithConfigurationService(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockRepoProvider := mock_services.NewMockRepositoryProvider(ctrl)
	mockTokenSigner := services.NewTokenSigner()
	mockTokenCache := mock_cache.NewMockTokenStore(ctrl)
	mockPkceRepo := mock_domain.NewMockPkceRepository(ctrl)
	mockConfigRepo := mock_domain.NewMockConfigurationRepository(ctrl)
	appConfig := &api.OpenIDProviderConfig{Issuer: "http://issuer.com"}
	mockAppConfig := &config.Config{}

	// Setup expectations for configuration service calls during service initialization
	// SMS configuration
	mockConfigRepo.EXPECT().GetByKey(context.Background(), domain.ConfigTypeSMS, "account_sid").Return(nil, domain.ErrConfigurationNotFound).AnyTimes()
	mockConfigRepo.EXPECT().GetByKey(context.Background(), domain.ConfigTypeSMS, "auth_token").Return(nil, domain.ErrConfigurationNotFound).AnyTimes()
	mockConfigRepo.EXPECT().GetByKey(context.Background(), domain.ConfigTypeSMS, "phone_number").Return(nil, domain.ErrConfigurationNotFound).AnyTimes()
	// Email configuration
	mockConfigRepo.EXPECT().GetByKey(context.Background(), domain.ConfigTypeEmail, "api_key").Return(nil, domain.ErrConfigurationNotFound).AnyTimes()
	mockConfigRepo.EXPECT().GetByKey(context.Background(), domain.ConfigTypeEmail, "from_email").Return(nil, domain.ErrConfigurationNotFound).AnyTimes()
	mockConfigRepo.EXPECT().GetByKey(context.Background(), domain.ConfigTypeEmail, "base_url").Return(nil, domain.ErrConfigurationNotFound).AnyTimes()
	// Push configuration
	mockConfigRepo.EXPECT().GetByKey(context.Background(), domain.ConfigTypePush, "project_id").Return(nil, domain.ErrConfigurationNotFound).AnyTimes()
	mockConfigRepo.EXPECT().GetByKey(context.Background(), domain.ConfigTypePush, "credentials_path").Return(nil, domain.ErrConfigurationNotFound).AnyTimes()

	setupMockRepoProviderForServiceGetters(mockRepoProvider, ctrl)
	mockRepoProvider.EXPECT().ConfigurationRepository(gomock.Any()).Return(mockConfigRepo).AnyTimes()

	// Create a valid 32-byte encryption key
	encryptionKey := "12345678901234567890123456789012" // 32 bytes

	opts := services.DefaultServiceProviderOptions{
		RepositoryProvider: mockRepoProvider,
		Config:             appConfig,
		AppConfig:          mockAppConfig,
		TokenSigner:        mockTokenSigner,
		TokenCache:         mockTokenCache,
		PkceRepository:     mockPkceRepo,
		EncryptionKey:      encryptionKey,
	}

	sp, err := services.NewDefaultServiceProvider(opts)
	require.NoError(t, err)
	require.NotNil(t, sp)

	// Configuration service should be initialized
	configService := sp.ConfigurationService()
	assert.NotNil(t, configService)

	// Services should be initialized (they use configuration service if available)
	pushService := sp.PushNotificationService()
	assert.NotNil(t, pushService)
}

func TestDefaultServiceProvider_InitializeServices_WithoutConfigurationService(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockRepoProvider := mock_services.NewMockRepositoryProvider(ctrl)
	mockTokenSigner := services.NewTokenSigner()
	mockTokenCache := mock_cache.NewMockTokenStore(ctrl)
	mockPkceRepo := mock_domain.NewMockPkceRepository(ctrl)
	appConfig := &api.OpenIDProviderConfig{Issuer: "http://issuer.com"}
	mockAppConfig := &config.Config{}

	setupMockRepoProviderForServiceGetters(mockRepoProvider, ctrl)

	opts := services.DefaultServiceProviderOptions{
		RepositoryProvider: mockRepoProvider,
		Config:             appConfig,
		AppConfig:          mockAppConfig,
		TokenSigner:        mockTokenSigner,
		TokenCache:         mockTokenCache,
		PkceRepository:     mockPkceRepo,
		// No EncryptionKey, so no ConfigurationService
	}

	sp, err := services.NewDefaultServiceProvider(opts)
	require.NoError(t, err)
	require.NotNil(t, sp)

	// Configuration service should be nil
	configService := sp.ConfigurationService()
	assert.Nil(t, configService)

	// Services should still be initialized (using app config fallback)
	pushService := sp.PushNotificationService()
	assert.NotNil(t, pushService)
}
