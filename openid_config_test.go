package ssso_test

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	ssso "github.com/pilab-dev/shadow-sso"
	"github.com/pilab-dev/shadow-sso/api"
	"github.com/pilab-dev/shadow-sso/cache"
	mock_domain "github.com/pilab-dev/shadow-sso/domain/mocks"
	"github.com/pilab-dev/shadow-sso/services"
	mock_services "github.com/pilab-dev/shadow-sso/services/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func setupMockRepoProvider(ctrl *gomock.Controller) *mock_services.MockRepositoryProvider {
	mockRepoProvider := mock_services.NewMockRepositoryProvider(ctrl)
	mockRepoProvider.EXPECT().UserRepository(gomock.Any()).Return(mock_domain.NewMockUserRepository(ctrl)).AnyTimes()
	mockRepoProvider.EXPECT().SessionRepository(gomock.Any()).Return(mock_domain.NewMockSessionRepository(ctrl)).AnyTimes()
	mockRepoProvider.EXPECT().UserFederatedIdentityRepository(gomock.Any()).Return(mock_domain.NewMockUserFederatedIdentityRepository(ctrl)).AnyTimes()
	mockRepoProvider.EXPECT().TokenRepository(gomock.Any()).Return(mock_domain.NewMockTokenRepository(ctrl)).AnyTimes()
	mockRepoProvider.EXPECT().AuthorizationCodeRepository(gomock.Any()).Return(mock_domain.NewMockAuthorizationCodeRepository(ctrl)).AnyTimes()
	mockRepoProvider.EXPECT().DeviceAuthorizationRepository(gomock.Any()).Return(mock_domain.NewMockDeviceAuthorizationRepository(ctrl)).AnyTimes()
	mockRepoProvider.EXPECT().ClientRepository(gomock.Any()).Return(mock_domain.NewMockClientRepository(ctrl)).AnyTimes()
	mockRepoProvider.EXPECT().PublicKeyRepository(gomock.Any()).Return(mock_domain.NewMockPublicKeyRepository(ctrl)).AnyTimes()
	mockRepoProvider.EXPECT().ServiceAccountRepository(gomock.Any()).Return(mock_domain.NewMockServiceAccountRepository(ctrl)).AnyTimes()
	mockRepoProvider.EXPECT().IdPRepository(gomock.Any()).Return(mock_domain.NewMockIdPRepository(ctrl)).AnyTimes()
	return mockRepoProvider
}

func TestNewSSOServer_HealthzEndpoint(t *testing.T) {
	gin.SetMode(gin.TestMode)

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	// Create minimal mocks
	mockRepoProvider := setupMockRepoProvider(ctrl)
	mockTokenSigner := services.NewTokenSigner()
	mockTokenCache := cache.NewMemoryTokenStore(1 * time.Hour)

	config := &api.OpenIDProviderConfig{
		Issuer:            "http://localhost:8080",
		AccessTokenTTL:    1 * time.Hour,
		RefreshTokenTTL:   24 * time.Hour,
		AuthCodeTTL:       10 * time.Minute,
		KeyRotationPeriod: 24 * time.Hour,
		SecurityConfig: api.SecurityConfig{
			AllowedSigningAlgs: []string{"HS256"},
		},
		TokenConfig: api.TokenConfig{
			AccessTokenFormat: "jwt",
		},
	}

	opts := ssso.SSOServerOptions{
		Config:             config,
		RepositoryProvider: mockRepoProvider,
		TokenSigner:        mockTokenSigner,
		TokenCache:         mockTokenCache,
	}

	router, err := ssso.NewSSOServer(opts)
	require.NoError(t, err)
	require.NotNil(t, router)

	// Test /healthz endpoint
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/healthz", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "OK", w.Body.String())
}

func TestNewSSOServer_ReadyzEndpoint(t *testing.T) {
	gin.SetMode(gin.TestMode)

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	// Create minimal mocks
	mockRepoProvider := setupMockRepoProvider(ctrl)
	mockTokenSigner := services.NewTokenSigner()
	mockTokenCache := cache.NewMemoryTokenStore(1 * time.Hour)

	config := &api.OpenIDProviderConfig{
		Issuer:            "http://localhost:8080",
		AccessTokenTTL:    1 * time.Hour,
		RefreshTokenTTL:   24 * time.Hour,
		AuthCodeTTL:       10 * time.Minute,
		KeyRotationPeriod: 24 * time.Hour,
		SecurityConfig: api.SecurityConfig{
			AllowedSigningAlgs: []string{"HS256"},
		},
		TokenConfig: api.TokenConfig{
			AccessTokenFormat: "jwt",
		},
	}

	opts := ssso.SSOServerOptions{
		Config:             config,
		RepositoryProvider: mockRepoProvider,
		TokenSigner:        mockTokenSigner,
		TokenCache:         mockTokenCache,
	}

	router, err := ssso.NewSSOServer(opts)
	require.NoError(t, err)
	require.NotNil(t, router)

	// Test /readyz endpoint (should work for non-MongoDB providers)
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/readyz", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "OK", w.Body.String())
}
