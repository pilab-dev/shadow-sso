package federation_test

import (
	"context"
	"errors"
	"testing"

	"github.com/pilab-dev/shadow-sso/domain"
	mock_domain "github.com/pilab-dev/shadow-sso/domain/mock"
	"github.com/pilab-dev/shadow-sso/internal/federation"
	mock_federation "github.com/pilab-dev/shadow-sso/internal/federation/mock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	"golang.org/x/oauth2"
)

func TestFederationService_GetAuthorizationURL(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockIdPRepo := mock_domain.NewMockIdPRepository(ctrl)
	fedService := federation.NewService(mockIdPRepo, "http://localhost/callback")

	mockProvider := mock_federation.NewMockOAuth2Provider(ctrl)
	mockProvider.EXPECT().Name().Return("mockprov").AnyTimes()
	mockProvider.EXPECT().GetAuthCodeURL("test_state", "http://localhost/callback/mockprov", gomock.Any()).Return("http://mockprovider.com/auth?state=test_state", nil)

	fedService.RegisterProvider(mockProvider)

	authURL, err := fedService.GetAuthorizationURL(context.Background(), "mockprov", "test_state")
	require.NoError(t, err)
	assert.Equal(t, "http://mockprovider.com/auth?state=test_state", authURL)
}

func TestFederationService_GetAuthorizationURL_ProviderNotFound(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockIdPRepo := mock_domain.NewMockIdPRepository(ctrl)
	fedService := federation.NewService(mockIdPRepo, "http://localhost/callback")

	mockIdPRepo.EXPECT().GetIdPByName(gomock.Any(), "unknownprov").Return(nil, errors.New("not found"))

	_, err := fedService.GetAuthorizationURL(context.Background(), "unknownprov", "test_state")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to load IdP config for unknownprov")
}

func TestFederationService_HandleCallback_Success(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockIdPRepo := mock_domain.NewMockIdPRepository(ctrl)
	fedService := federation.NewService(mockIdPRepo, "http://localhost/callback")

	mockProvider := mock_federation.NewMockOAuth2Provider(ctrl)
	expectedToken := &oauth2.Token{AccessToken: "valid_access_token"}
	expectedUserInfo := &federation.ExternalUserInfo{ProviderUserID: "ext123", Email: "user@provider.com"}

	mockProvider.EXPECT().Name().Return("mockprov").AnyTimes()
	mockProvider.EXPECT().ExchangeCode(gomock.Any(), "http://localhost/callback/mockprov", "auth_code", gomock.Any()).Return(expectedToken, nil)
	mockProvider.EXPECT().FetchUserInfo(gomock.Any(), expectedToken).Return(expectedUserInfo, nil)

	fedService.RegisterProvider(mockProvider)

	userInfo, token, err := fedService.HandleCallback(context.Background(), "mockprov", "session_state_val", "session_state_val", "auth_code")
	require.NoError(t, err)
	assert.Equal(t, expectedToken, token)
	assert.Equal(t, expectedUserInfo, userInfo)
}

func TestFederationService_HandleCallback_InvalidState(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockIdPRepo := mock_domain.NewMockIdPRepository(ctrl) // Not strictly needed as GetProvider won't be called if state fails early
	fedService := federation.NewService(mockIdPRepo, "http://localhost/callback")

	// No need to mock provider as it should fail before provider interaction

	_, _, err := fedService.HandleCallback(context.Background(), "mockprov", "query_state", "different_session_state", "auth_code")
	require.Error(t, err)
	assert.True(t, errors.Is(err, federation.ErrInvalidAuthState), "Error should be ErrInvalidAuthState")
}

func TestFederationService_HandleCallback_ExchangeCodeError(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockIdPRepo := mock_domain.NewMockIdPRepository(ctrl)
	fedService := federation.NewService(mockIdPRepo, "http://localhost/callback")

	mockProvider := mock_federation.NewMockOAuth2Provider(ctrl)
	mockProvider.EXPECT().Name().Return("mockprov").AnyTimes()
	mockProvider.EXPECT().ExchangeCode(gomock.Any(), "http://localhost/callback/mockprov", "auth_code", gomock.Any()).Return(nil, errors.New("exchange failed"))

	fedService.RegisterProvider(mockProvider)

	_, _, err := fedService.HandleCallback(context.Background(), "mockprov", "s", "s", "auth_code")
	require.Error(t, err)
	assert.True(t, errors.Is(err, federation.ErrExchangeCodeFailed), "Error should wrap ErrExchangeCodeFailed")
	assert.Contains(t, err.Error(), "exchange failed")
}

func TestFederationService_HandleCallback_FetchUserInfoError(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockIdPRepo := mock_domain.NewMockIdPRepository(ctrl)
	fedService := federation.NewService(mockIdPRepo, "http://localhost/callback")

	mockProvider := mock_federation.NewMockOAuth2Provider(ctrl)
	expectedToken := &oauth2.Token{AccessToken: "valid_access_token"}

	mockProvider.EXPECT().Name().Return("mockprov").AnyTimes()
	mockProvider.EXPECT().ExchangeCode(gomock.Any(), "http://localhost/callback/mockprov", "auth_code", gomock.Any()).Return(expectedToken, nil)
	mockProvider.EXPECT().FetchUserInfo(gomock.Any(), expectedToken).Return(nil, errors.New("fetch failed"))

	fedService.RegisterProvider(mockProvider)

	_, _, err := fedService.HandleCallback(context.Background(), "mockprov", "s", "s", "auth_code")
	require.Error(t, err)
	assert.True(t, errors.Is(err, federation.ErrFetchUserInfoFailed), "Error should wrap ErrFetchUserInfoFailed")
	assert.Contains(t, err.Error(), "fetch failed")
}

func TestFederationService_GetProvider_Registered(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockIdPRepo := mock_domain.NewMockIdPRepository(ctrl) // Not called if provider is in registry
	service := federation.NewService(mockIdPRepo, "http://localhost/callback")

	mockProv := mock_federation.NewMockOAuth2Provider(ctrl)
	mockProv.EXPECT().Name().Return("registered_provider").AnyTimes()
	service.RegisterProvider(mockProv)

	p, err := service.GetProvider(context.Background(), "registered_provider")
	require.NoError(t, err)
	assert.Equal(t, mockProv, p)
}

func TestFederationService_GetProvider_FromRepo_Google(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockIdPRepo := mock_domain.NewMockIdPRepository(ctrl)
	service := federation.NewService(mockIdPRepo, "http://localhost/callback")

	googleConfig := &domain.IdentityProvider{
		ID: "google-id", Name: "google", Type: domain.IdPTypeOIDC, IsEnabled: true,
		OIDCClientID: "google-client", OIDCClientSecret: "google-secret",
		OIDCIssuerURL: "https://accounts.google.com", OIDCScopes: []string{"openid", "email"},
	}
	mockIdPRepo.EXPECT().GetIdPByName(gomock.Any(), "google").Return(googleConfig, nil)

	p, err := service.GetProvider(context.Background(), "google")
	require.NoError(t, err)
	require.NotNil(t, p)
	_, ok := p.(*federation.GoogleProvider) // Check if it's the correct type
	assert.True(t, ok, "Expected GoogleProvider type")

	// Check if the config was passed correctly
	gp := p.(*federation.GoogleProvider)
	assert.Equal(t, googleConfig.OIDCClientID, gp.Config.OIDCClientID)
}

func TestFederationService_GetProvider_FromRepo_GitHub(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockIdPRepo := mock_domain.NewMockIdPRepository(ctrl)
	service := federation.NewService(mockIdPRepo, "http://localhost/callback")

	githubConfig := &domain.IdentityProvider{
		ID: "gh-id", Name: "github", Type: domain.IdPTypeOIDC, IsEnabled: true, // Type can be OIDC for GitHub in our system
		OIDCClientID: "gh-client", OIDCClientSecret: "gh-secret",
		OIDCScopes: []string{"read:user"},
	}
	mockIdPRepo.EXPECT().GetIdPByName(gomock.Any(), "github").Return(githubConfig, nil)

	p, err := service.GetProvider(context.Background(), "github")
	require.NoError(t, err)
	_, ok := p.(*federation.GitHubProvider)
	assert.True(t, ok, "Expected GitHubProvider type")
}

func TestFederationService_GetProvider_FromRepo_Facebook(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockIdPRepo := mock_domain.NewMockIdPRepository(ctrl)
	service := federation.NewService(mockIdPRepo, "http://localhost/callback")

	fbConfig := &domain.IdentityProvider{
		ID: "fb-id", Name: "facebook", Type: domain.IdPTypeOIDC, IsEnabled: true,
		OIDCClientID: "fb-client", OIDCClientSecret: "fb-secret",
		OIDCScopes: []string{"email"},
	}
	mockIdPRepo.EXPECT().GetIdPByName(gomock.Any(), "facebook").Return(fbConfig, nil)

	p, err := service.GetProvider(context.Background(), "facebook")
	require.NoError(t, err)
	_, ok := p.(*federation.FacebookProvider)
	assert.True(t, ok, "Expected FacebookProvider type")
}

func TestFederationService_GetProvider_FromRepo_Apple(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockIdPRepo := mock_domain.NewMockIdPRepository(ctrl)
	service := federation.NewService(mockIdPRepo, "http://localhost/callback")

	appleConfig := &domain.IdentityProvider{
		ID: "apple-id", Name: "apple", Type: domain.IdPTypeOIDC, IsEnabled: true,
		OIDCClientID: "apple-client", OIDCClientSecret: "apple-secret-jwt",
		OIDCIssuerURL: "https://appleid.apple.com", OIDCScopes: []string{"name", "email"},
	}
	mockIdPRepo.EXPECT().GetIdPByName(gomock.Any(), "apple").Return(appleConfig, nil)

	p, err := service.GetProvider(context.Background(), "apple")
	require.NoError(t, err)
	_, ok := p.(*federation.AppleProvider)
	assert.True(t, ok, "Expected AppleProvider type")
}

func TestFederationService_GetProvider_NotEnabled(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockIdPRepo := mock_domain.NewMockIdPRepository(ctrl)
	service := federation.NewService(mockIdPRepo, "http://localhost/callback")

	disabledConfig := &domain.IdentityProvider{Name: "disabledprov", IsEnabled: false}
	mockIdPRepo.EXPECT().GetIdPByName(gomock.Any(), "disabledprov").Return(disabledConfig, nil)

	_, err := service.GetProvider(context.Background(), "disabledprov")
	require.Error(t, err)
	assert.True(t, errors.Is(err, federation.ErrProviderNotFound))
}

func TestFederationService_GetProvider_UnsupportedType(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockIdPRepo := mock_domain.NewMockIdPRepository(ctrl)
	service := federation.NewService(mockIdPRepo, "http://localhost/callback")

	samlConfig := &domain.IdentityProvider{Name: "samlprov", Type: domain.IdPTypeSAML, IsEnabled: true}
	mockIdPRepo.EXPECT().GetIdPByName(gomock.Any(), "samlprov").Return(samlConfig, nil)

	_, err := service.GetProvider(context.Background(), "samlprov")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported provider: samlprov (type: SAML)")
}

func TestFederationService_getRedirectURLForProvider(t *testing.T) {
	tests := []struct {
		name               string
		defaultRedirectURL string
		providerName       string
		expectedURL        string
	}{
		{"no trailing slash", "http://localhost/cb", "google", "http://localhost/cb/google"},
		{"with trailing slash", "http://localhost/cb/", "google", "http://localhost/cb/google"},
		{"provider with spaces", "http://localhost/cb", "my provider", "http://localhost/cb/my%20provider"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			service := federation.NewService(nil, tt.defaultRedirectURL)
			actualURL := service.GetRedirectURLForProvider(tt.providerName)
			assert.Equal(t, tt.expectedURL, actualURL)
		})
	}
}
