package webauth_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/pilab-dev/shadow-sso/api/webauth"
	"github.com/pilab-dev/shadow-sso/domain"
	mock_domain "github.com/pilab-dev/shadow-sso/domain/mocks"
	services_mocks "github.com/pilab-dev/shadow-sso/services/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func setupSocialTest(t *testing.T) (
	*gin.Engine,
	*gomock.Controller,
	*mock_domain.MockFlowStore,
	*mock_domain.MockIdPRepository,
	*services_mocks.MockFederationService,
) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	ctrl := gomock.NewController(t)

	mockFlowStore := mock_domain.NewMockFlowStore(ctrl)
	mockIdPRepo := mock_domain.NewMockIdPRepository(ctrl)
	mockFederationService := services_mocks.NewMockFederationService(ctrl)

	cfg := webauth.DefaultConfig()
	wa := webauth.New(&webauth.Options{
		UserRepo:          mock_domain.NewMockUserRepository(ctrl),
		PasswordHasher:    mock_domain.NewMockPasswordHasher(ctrl),
		FlowStore:         mockFlowStore,
		UserSessionStore:  mock_domain.NewMockUserSessionStore(ctrl),
		IdPRepository:     mockIdPRepo,
		FederationService: mockFederationService,
		OAuthService:      services_mocks.NewMockOAuthService(ctrl),
		TokenService:      services_mocks.NewMockTokenService(ctrl),
		ClientService:     services_mocks.NewMockClientService(ctrl),
		Config:            cfg,
		SSOCookieSecret:   "test-secret-32-bytes-long-for-hmac-sha256!!",
	})

	router := gin.New()
	router.LoadHTMLGlob("templates/*.html")
	router.GET("/login/:provider", wa.SocialLoginHandler)

	return router, ctrl, mockFlowStore, mockIdPRepo, mockFederationService
}

func TestSocialLoginHandler_ValidProvider_NoFlowID(t *testing.T) {
	// Given
	router, ctrl, _, mockIdPRepo, mockFederationService := setupSocialTest(t)
	defer ctrl.Finish()

	mockIdPRepo.EXPECT().GetIdPByName(gomock.Any(), "google").Return(&domain.IdentityProvider{
		Name:      "google",
		IsEnabled: true,
	}, nil)
	mockFederationService.EXPECT().GetAuthorizationURL(gomock.Any(), "google", gomock.Any()).Return(
		"https://accounts.google.com/o/oauth2/auth?client_id=test", nil,
	)

	// When
	req := httptest.NewRequest("GET", "/login/google", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Then
	require.Equal(t, http.StatusFound, w.Code)
	assert.Contains(t, w.Header().Get("Location"), "https://accounts.google.com/o/oauth2/auth")
	// Verify state cookie was set
	cookies := w.Result().Cookies()
	var found bool
	for _, c := range cookies {
		if c.Name == "sso_oauth_state" {
			found = true
			assert.NotEmpty(t, c.Value)
			assert.True(t, c.HttpOnly)
			assert.Equal(t, "/", c.Path)
			break
		}
	}
	assert.True(t, found, "expected sso_oauth_state cookie to be set")
}

func TestSocialLoginHandler_ValidProvider_WithFlowID(t *testing.T) {
	// Given
	router, ctrl, mockFlowStore, mockIdPRepo, mockFederationService := setupSocialTest(t)
	defer ctrl.Finish()

	flowState := &domain.LoginFlowState{
		FlowID: "test-flow",
	}
	mockFlowStore.EXPECT().GetFlow("test-flow").Return(flowState, nil)
	mockIdPRepo.EXPECT().GetIdPByName(gomock.Any(), "google").Return(&domain.IdentityProvider{
		Name:      "google",
		IsEnabled: true,
	}, nil)
	mockFederationService.EXPECT().GetAuthorizationURL(gomock.Any(), "google", gomock.Any()).Return(
		"https://accounts.google.com/o/oauth2/auth?client_id=test", nil,
	)

	// When
	req := httptest.NewRequest("GET", "/login/google", nil)
	req.AddCookie(&http.Cookie{Name: "sso_oidc_flow_id", Value: "test-flow"})
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Then
	require.Equal(t, http.StatusFound, w.Code)
	assert.Contains(t, w.Header().Get("Location"), "https://accounts.google.com/o/oauth2/auth")
}

func TestSocialLoginHandler_UnknownProvider(t *testing.T) {
	// Given
	router, ctrl, _, mockIdPRepo, _ := setupSocialTest(t)
	defer ctrl.Finish()

	mockIdPRepo.EXPECT().GetIdPByName(gomock.Any(), "unknown").Return(nil, errors.New("not found"))

	// When
	req := httptest.NewRequest("GET", "/login/unknown", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Then
	require.Equal(t, http.StatusNotFound, w.Code)
	assert.Contains(t, w.Body.String(), "Unknown identity provider")
}

func TestSocialLoginHandler_DisabledProvider(t *testing.T) {
	// Given
	router, ctrl, _, mockIdPRepo, _ := setupSocialTest(t)
	defer ctrl.Finish()

	mockIdPRepo.EXPECT().GetIdPByName(gomock.Any(), "disabled-idp").Return(&domain.IdentityProvider{
		Name:      "disabled-idp",
		IsEnabled: false,
	}, nil)

	// When
	req := httptest.NewRequest("GET", "/login/disabled-idp", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Then
	require.Equal(t, http.StatusNotFound, w.Code)
	assert.Contains(t, w.Body.String(), "Unknown identity provider")
}

func TestSocialLoginHandler_InvalidFlowID(t *testing.T) {
	// Given
	router, ctrl, mockFlowStore, _, _ := setupSocialTest(t)
	defer ctrl.Finish()

	mockFlowStore.EXPECT().GetFlow("bad-flow").Return(nil, errors.New("flow not found"))

	// When
	req := httptest.NewRequest("GET", "/login/google", nil)
	req.AddCookie(&http.Cookie{Name: "sso_oidc_flow_id", Value: "bad-flow"})
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Then
	require.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "Invalid or expired login request")
}

func TestSocialLoginHandler_FederationServiceError(t *testing.T) {
	// Given
	router, ctrl, _, mockIdPRepo, mockFederationService := setupSocialTest(t)
	defer ctrl.Finish()

	mockIdPRepo.EXPECT().GetIdPByName(gomock.Any(), "google").Return(&domain.IdentityProvider{
		Name:      "google",
		IsEnabled: true,
	}, nil)
	mockFederationService.EXPECT().GetAuthorizationURL(gomock.Any(), "google", gomock.Any()).Return(
		"", errors.New("federation service unavailable"),
	)

	// When
	req := httptest.NewRequest("GET", "/login/google", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Then
	require.Equal(t, http.StatusInternalServerError, w.Code)
	assert.Contains(t, w.Body.String(), "Failed to initiate login")
}
