package webauth_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/pilab-dev/shadow-sso/api/webauth"
	"github.com/pilab-dev/shadow-sso/domain"
	mock_domain "github.com/pilab-dev/shadow-sso/domain/mocks"
	services_mocks "github.com/pilab-dev/shadow-sso/services/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func setupConsentTest(t *testing.T) (
	*gin.Engine,
	*gomock.Controller,
	*mock_domain.MockFlowStore,
	*services_mocks.MockClientService,
	*services_mocks.MockOAuthService,
) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	ctrl := gomock.NewController(t)

	mockFlowStore := mock_domain.NewMockFlowStore(ctrl)
	mockUserRepo := mock_domain.NewMockUserRepository(ctrl)
	mockIdPRepo := mock_domain.NewMockIdPRepository(ctrl)
	mockPasswordHasher := mock_domain.NewMockPasswordHasher(ctrl)
	mockFederationService := services_mocks.NewMockFederationService(ctrl)
	mockOAuthService := services_mocks.NewMockOAuthService(ctrl)
	mockClientService := services_mocks.NewMockClientService(ctrl)

	cfg := webauth.DefaultConfig()
	wa := webauth.New(&webauth.Options{
		UserRepo:          mockUserRepo,
		PasswordHasher:    mockPasswordHasher,
		FlowStore:         mockFlowStore,
		UserSessionStore:  mock_domain.NewMockUserSessionStore(ctrl),
		IdPRepository:     mockIdPRepo,
		FederationService: mockFederationService,
		OAuthService:      mockOAuthService,
		TokenService:      services_mocks.NewMockTokenService(ctrl),
		ClientService:     mockClientService,
		Config:            cfg,
		SSOCookieSecret:   "test-secret-32-bytes-long-for-hmac-sha256!!",
	})

	router := gin.New()
	router.LoadHTMLGlob("templates/*.html")
	router.GET("/consent", wa.ConsentPageHandler)
	router.POST("/consent", wa.ConsentSubmitHandler)

	return router, ctrl, mockFlowStore, mockClientService, mockOAuthService
}

// --- ConsentPageHandler tests ---

func TestConsentPage_Success(t *testing.T) {
	router, ctrl, mockFlowStore, mockClientService, _ := setupConsentTest(t)
	defer ctrl.Finish()

	flowState := &domain.LoginFlowState{
		FlowID:    "valid-flow",
		ClientID:  "test-client",
		Scope:     "openid profile email",
		ExpiresAt: time.Now().Add(10 * time.Minute),
	}
	mockFlowStore.EXPECT().GetFlow("valid-flow").Return(flowState, nil)
	mockClientService.EXPECT().GetClient(gomock.Any(), "test-client").Return(&domain.Client{
		ID:             "test-client",
		Name:           "My App",
		RequireConsent: true,
	}, nil)

	req := httptest.NewRequest("GET", "/consent", nil)
	req.AddCookie(&http.Cookie{Name: "sso_oidc_flow_id", Value: "valid-flow"})
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "Authorization Required")
}

func TestConsentPage_NoFlowID(t *testing.T) {
	router, ctrl, _, _, _ := setupConsentTest(t)
	defer ctrl.Finish()

	req := httptest.NewRequest("GET", "/consent", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "Missing consent request identifier")
}

func TestConsentPage_InvalidFlow(t *testing.T) {
	router, ctrl, mockFlowStore, _, _ := setupConsentTest(t)
	defer ctrl.Finish()

	mockFlowStore.EXPECT().GetFlow("invalid-flow").Return(nil, errors.New("flow not found"))

	req := httptest.NewRequest("GET", "/consent", nil)
	req.AddCookie(&http.Cookie{Name: "sso_oidc_flow_id", Value: "invalid-flow"})
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "Invalid or expired consent request")
}

func TestConsentPage_ExpiredFlow(t *testing.T) {
	router, ctrl, mockFlowStore, _, _ := setupConsentTest(t)
	defer ctrl.Finish()

	flowState := &domain.LoginFlowState{
		FlowID:    "expired-flow",
		ClientID:  "test-client",
		ExpiresAt: time.Now().Add(-10 * time.Minute),
	}
	mockFlowStore.EXPECT().GetFlow("expired-flow").Return(flowState, nil)
	mockFlowStore.EXPECT().DeleteFlow("expired-flow").Return(nil)

	req := httptest.NewRequest("GET", "/consent", nil)
	req.AddCookie(&http.Cookie{Name: "sso_oidc_flow_id", Value: "expired-flow"})
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "Consent request has expired")
}

func TestConsentPage_ClientServiceError(t *testing.T) {
	router, ctrl, mockFlowStore, mockClientService, _ := setupConsentTest(t)
	defer ctrl.Finish()

	flowState := &domain.LoginFlowState{
		FlowID:    "valid-flow",
		ClientID:  "test-client",
		ExpiresAt: time.Now().Add(10 * time.Minute),
	}
	mockFlowStore.EXPECT().GetFlow("valid-flow").Return(flowState, nil)
	mockClientService.EXPECT().GetClient(gomock.Any(), "test-client").Return(nil, errors.New("client not found"))

	req := httptest.NewRequest("GET", "/consent", nil)
	req.AddCookie(&http.Cookie{Name: "sso_oidc_flow_id", Value: "valid-flow"})
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusInternalServerError, w.Code)
	assert.Contains(t, w.Body.String(), "Failed to load application details")
}

// --- ConsentSubmitHandler tests ---

func TestConsentSubmit_Approve(t *testing.T) {
	router, ctrl, mockFlowStore, _, mockOAuthService := setupConsentTest(t)
	defer ctrl.Finish()

	flowState := &domain.LoginFlowState{
		FlowID:    "valid-flow",
		ClientID:  "test-client",
		UserID:    "user-123",
		Scope:     "openid profile",
		RedirectURI: "http://localhost/callback",
		State:     "my-state",
		ExpiresAt: time.Now().Add(10 * time.Minute),
	}
	mockFlowStore.EXPECT().GetFlow("valid-flow").Return(flowState, nil)
	mockOAuthService.EXPECT().GenerateAuthCode(
		gomock.Any(),
		"test-client",
		"user-123",
		"http://localhost/callback",
		"openid profile",
		"",
		"",
		"",
		gomock.Any(),
	).Return("auth-code-abc", nil)
	mockFlowStore.EXPECT().DeleteFlow("valid-flow").Return(nil)

	form := url.Values{}
	form.Set("decision", "approve")
	form.Set("csrf_token", "test-csrf")

	req := httptest.NewRequest("POST", "/consent", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: "sso_csrf_token", Value: "test-csrf"})
	req.AddCookie(&http.Cookie{Name: "sso_oidc_flow_id", Value: "valid-flow"})
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusFound, w.Code)
	location := w.Header().Get("Location")
	assert.Contains(t, location, "http://localhost/callback")
	assert.Contains(t, location, "code=auth-code-abc")
	assert.Contains(t, location, "state=my-state")
}

func TestConsentSubmit_Deny(t *testing.T) {
	router, ctrl, mockFlowStore, _, _ := setupConsentTest(t)
	defer ctrl.Finish()

	flowState := &domain.LoginFlowState{
		FlowID:      "valid-flow",
		ClientID:    "test-client",
		RedirectURI: "http://localhost/callback",
		State:       "my-state",
		ExpiresAt:   time.Now().Add(10 * time.Minute),
	}
	mockFlowStore.EXPECT().GetFlow("valid-flow").Return(flowState, nil)
	mockFlowStore.EXPECT().DeleteFlow("valid-flow").Return(nil)

	form := url.Values{}
	form.Set("decision", "deny")
	form.Set("csrf_token", "test-csrf")

	req := httptest.NewRequest("POST", "/consent", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: "sso_csrf_token", Value: "test-csrf"})
	req.AddCookie(&http.Cookie{Name: "sso_oidc_flow_id", Value: "valid-flow"})
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusFound, w.Code)
	location := w.Header().Get("Location")
	assert.Contains(t, location, "error=access_denied")
	assert.Contains(t, location, "state=my-state")
}

func TestConsentSubmit_MissingCSRF(t *testing.T) {
	router, ctrl, _, _, _ := setupConsentTest(t)
	defer ctrl.Finish()

	form := url.Values{}
	form.Set("decision", "approve")

	req := httptest.NewRequest("POST", "/consent", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "Invalid form submission")
}

func TestConsentSubmit_MissingFlowID(t *testing.T) {
	router, ctrl, _, _, _ := setupConsentTest(t)
	defer ctrl.Finish()

	form := url.Values{}
	form.Set("decision", "approve")
	form.Set("csrf_token", "test-csrf")

	req := httptest.NewRequest("POST", "/consent", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: "sso_csrf_token", Value: "test-csrf"})
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "Missing consent request identifier")
}

func TestConsentSubmit_InvalidFlow(t *testing.T) {
	router, ctrl, mockFlowStore, _, _ := setupConsentTest(t)
	defer ctrl.Finish()

	mockFlowStore.EXPECT().GetFlow("invalid-flow").Return(nil, errors.New("flow not found"))

	form := url.Values{}
	form.Set("decision", "approve")
	form.Set("csrf_token", "test-csrf")

	req := httptest.NewRequest("POST", "/consent", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: "sso_csrf_token", Value: "test-csrf"})
	req.AddCookie(&http.Cookie{Name: "sso_oidc_flow_id", Value: "invalid-flow"})
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "Invalid or expired consent request")
}

func TestConsentSubmit_ExpiredFlow(t *testing.T) {
	router, ctrl, mockFlowStore, _, _ := setupConsentTest(t)
	defer ctrl.Finish()

	flowState := &domain.LoginFlowState{
		FlowID:    "expired-flow",
		ClientID:  "test-client",
		ExpiresAt: time.Now().Add(-10 * time.Minute),
	}
	mockFlowStore.EXPECT().GetFlow("expired-flow").Return(flowState, nil)
	mockFlowStore.EXPECT().DeleteFlow("expired-flow").Return(nil)

	form := url.Values{}
	form.Set("decision", "approve")
	form.Set("csrf_token", "test-csrf")

	req := httptest.NewRequest("POST", "/consent", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: "sso_csrf_token", Value: "test-csrf"})
	req.AddCookie(&http.Cookie{Name: "sso_oidc_flow_id", Value: "expired-flow"})
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "Consent request has expired")
}

func TestConsentSubmit_DenyNoRedirectURI(t *testing.T) {
	router, ctrl, mockFlowStore, _, _ := setupConsentTest(t)
	defer ctrl.Finish()

	flowState := &domain.LoginFlowState{
		FlowID:    "valid-flow",
		ClientID:  "test-client",
		ExpiresAt: time.Now().Add(10 * time.Minute),
	}
	mockFlowStore.EXPECT().GetFlow("valid-flow").Return(flowState, nil)
	mockFlowStore.EXPECT().DeleteFlow("valid-flow").Return(nil)

	form := url.Values{}
	form.Set("decision", "deny")
	form.Set("csrf_token", "test-csrf")

	req := httptest.NewRequest("POST", "/consent", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: "sso_csrf_token", Value: "test-csrf"})
	req.AddCookie(&http.Cookie{Name: "sso_oidc_flow_id", Value: "valid-flow"})
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "Access denied")
}
