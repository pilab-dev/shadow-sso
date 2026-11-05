package ssso_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	ssso "github.com/pilab-dev/shadow-sso"
	"github.com/pilab-dev/shadow-sso/api"
	"github.com/pilab-dev/shadow-sso/cache"
	"github.com/pilab-dev/shadow-sso/domain"
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
	// NewSSOServer idempotently bootstraps the built-in "sssoctl" client; report it as already present.
	mockClientRepo := mock_domain.NewMockClientRepository(ctrl)
	mockClientRepo.EXPECT().GetClient(gomock.Any(), "sssoctl").Return(&domain.Client{ID: "sssoctl"}, nil).AnyTimes()
	mockRepoProvider.EXPECT().ClientRepository(gomock.Any()).Return(mockClientRepo).AnyTimes()
	mockRepoProvider.EXPECT().PublicKeyRepository(gomock.Any()).Return(mock_domain.NewMockPublicKeyRepository(ctrl)).AnyTimes()
	mockRepoProvider.EXPECT().ServiceAccountRepository(gomock.Any()).Return(mock_domain.NewMockServiceAccountRepository(ctrl)).AnyTimes()
	mockRepoProvider.EXPECT().IdPRepository(gomock.Any()).Return(mock_domain.NewMockIdPRepository(ctrl)).AnyTimes()
	mockRepoProvider.EXPECT().GroupRepository(gomock.Any()).Return(mock_domain.NewMockGroupRepository(ctrl)).AnyTimes()
	mockRepoProvider.EXPECT().RoleRepository(gomock.Any()).Return(mock_domain.NewMockRoleRepository(ctrl)).AnyTimes()
	mockRepoProvider.EXPECT().RealmKeysRepository(gomock.Any()).Return(mock_domain.NewMockRealmKeysRepository(ctrl)).AnyTimes()
	mockRepoProvider.EXPECT().UserAttributeRepository(gomock.Any()).Return(mock_domain.NewMockUserAttributeRepository(ctrl)).AnyTimes()
	mockRepoProvider.EXPECT().UserAttributeMapperRepository(gomock.Any()).Return(mock_domain.NewMockUserAttributeMapperRepository(ctrl)).AnyTimes()
	mockRepoProvider.EXPECT().ProtocolMapperRepository(gomock.Any()).Return(mock_domain.NewMockProtocolMapperRepository(ctrl)).AnyTimes()
	mockRepoProvider.EXPECT().ClientScopeRepository(gomock.Any()).Return(mock_domain.NewMockClientScopeRepository(ctrl)).AnyTimes()
	mockRealmSettings := mock_domain.NewMockRealmSettingsRepository(ctrl)
	mockRealmSettings.EXPECT().GetRealmSettings(gomock.Any()).Return(&domain.RealmSettings{}, nil).AnyTimes()
	mockRepoProvider.EXPECT().RealmSettingsRepository(gomock.Any()).Return(mockRealmSettings).AnyTimes()
	mockRepoProvider.EXPECT().AuditLogRepository(gomock.Any()).Return(mock_domain.NewMockAuditLogRepository(ctrl)).AnyTimes()
	mockRepoProvider.EXPECT().PkceRepository(gomock.Any()).Return(mock_domain.NewMockPkceRepository(ctrl)).AnyTimes()
	mockRepoProvider.EXPECT().ConfigurationRepository(gomock.Any()).Return(mock_domain.NewMockConfigurationRepository(ctrl)).AnyTimes()
	return mockRepoProvider
}

func buildTestOpts(ctrl *gomock.Controller) ssso.SSOServerOptions {
	return ssso.SSOServerOptions{
		Config: &api.OpenIDProviderConfig{
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
		},
		RepositoryProvider: setupMockRepoProvider(ctrl),
		TokenSigner:        services.NewTokenSigner(),
		TokenCache:         cache.NewMemoryTokenStore(1 * time.Hour),
	}
}

// /healthz and /readyz are served exclusively by the management server (separate port).
// The main SSO router must not expose them so that probe traffic never hits the SSO listener.

// TestNewSSOServer_OIDCAdminConnectServicesRegistered ensures the new admin
// RPCs are mounted on the router. Unauthenticated requests must reach the auth
// interceptor (401) rather than 404, which would mean the handler is missing.
func TestNewSSOServer_OIDCAdminConnectServicesRegistered(t *testing.T) {
	gin.SetMode(gin.TestMode)

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	router, err := ssso.NewSSOServer(context.Background(), buildTestOpts(ctrl))
	require.NoError(t, err)

	for _, path := range []string{
		"/sso.v1.ProtocolMapperService/ListProtocolMappers",
		"/sso.v1.ClientScopeService/ListClientScopes",
		"/sso.v1.OIDCConfigurationService/GetOIDCConfiguration",
	} {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodPost, path, strings.NewReader("{}"))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code, "%s must be registered and require authentication", path)
	}
}

func TestNewSSOServer_HealthzNotOnSSORouter(t *testing.T) {
	gin.SetMode(gin.TestMode)

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	router, err := ssso.NewSSOServer(context.Background(), buildTestOpts(ctrl))
	require.NoError(t, err)
	require.NotNil(t, router)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/healthz", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code, "/healthz must not be registered on the SSO router")
}

func TestValidateConfig_NonPositiveAccessTokenTTL_ReturnsError(t *testing.T) {
	cfg := &api.OpenIDProviderConfig{
		Issuer:         "http://localhost:8080",
		AccessTokenTTL: 0,
		TokenConfig: api.TokenConfig{
			AccessTokenFormat: "jwt",
		},
		SecurityConfig: api.SecurityConfig{
			AllowedSigningAlgs: []string{"HS256"},
		},
	}
	cfg.AuthCodeTTL = 10 * time.Minute
	cfg.RefreshTokenTTL = 24 * time.Hour

	err := ssso.ValidateConfig(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "access token TTL must be positive")
}

func TestValidateConfig_NegativeRefreshTokenTTL_ReturnsError(t *testing.T) {
	cfg := &api.OpenIDProviderConfig{
		Issuer:          "http://localhost:8080",
		AccessTokenTTL:  1 * time.Hour,
		RefreshTokenTTL: -5 * time.Minute,
		AuthCodeTTL:     10 * time.Minute,
		TokenConfig: api.TokenConfig{
			AccessTokenFormat: "jwt",
		},
		SecurityConfig: api.SecurityConfig{
			AllowedSigningAlgs: []string{"HS256"},
		},
	}

	err := ssso.ValidateConfig(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "refresh token TTL must be positive")
}

func TestValidateConfig_NegativeAuthCodeTTL_ReturnsError(t *testing.T) {
	cfg := &api.OpenIDProviderConfig{
		Issuer:          "http://localhost:8080",
		AccessTokenTTL:  1 * time.Hour,
		RefreshTokenTTL: 24 * time.Hour,
		AuthCodeTTL:     0,
		TokenConfig: api.TokenConfig{
			AccessTokenFormat: "jwt",
		},
		SecurityConfig: api.SecurityConfig{
			AllowedSigningAlgs: []string{"HS256"},
		},
	}

	err := ssso.ValidateConfig(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "auth code TTL must be positive")
}

func TestNewSSOServer_ReadyzNotOnSSORouter(t *testing.T) {
	gin.SetMode(gin.TestMode)

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	router, err := ssso.NewSSOServer(context.Background(), buildTestOpts(ctrl))
	require.NoError(t, err)
	require.NotNil(t, router)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/readyz", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code, "/readyz must not be registered on the SSO router")
}
