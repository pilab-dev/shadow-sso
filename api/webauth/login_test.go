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
	"golang.org/x/crypto/bcrypt"
)

func setupLoginTest(t *testing.T) (
	*gin.Engine,
	*gomock.Controller,
	*mock_domain.MockFlowStore,
	*mock_domain.MockUserRepository,
	*mock_domain.MockIdPRepository,
	*mock_domain.MockPasswordHasher,
	*services_mocks.MockFederationService,
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
		ClientService:     services_mocks.NewMockClientService(ctrl),
		Config:            cfg,
		SSOCookieSecret:   "test-secret-32-bytes-long-for-hmac-sha256!!",
	})

	router := gin.New()
	router.LoadHTMLGlob("templates/*.html")
	router.GET("/login", wa.LoginPageHandler)
	router.POST("/login", wa.LoginSubmitHandler)
	router.GET("/login/:provider", wa.SocialLoginHandler)
	router.GET("/consent", wa.ConsentPageHandler)
	router.POST("/consent", wa.ConsentSubmitHandler)

	return router, ctrl, mockFlowStore, mockUserRepo, mockIdPRepo, mockPasswordHasher, mockFederationService, mockOAuthService
}

func TestLoginPage_NoFlowID(t *testing.T) {
	// Given
	router, ctrl, _, _, _, _, _, _ := setupLoginTest(t)
	defer ctrl.Finish()

	// When
	req := httptest.NewRequest("GET", "/login", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Then
	require.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "Missing login request identifier")
}

func TestLoginPage_InvalidFlow(t *testing.T) {
	// Given
	router, ctrl, mockFlowStore, _, _, _, _, _ := setupLoginTest(t)
	defer ctrl.Finish()

	mockFlowStore.EXPECT().GetFlow(gomock.Any(), "invalid-flow").Return(nil, errors.New("flow not found"))

	// When
	req := httptest.NewRequest("GET", "/login", nil)
	req.AddCookie(&http.Cookie{Name: "sso_oidc_flow_id", Value: "invalid-flow"})
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Then
	require.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "Invalid or expired login request")
}

func TestLoginPage_Success(t *testing.T) {
	// Given
	router, ctrl, mockFlowStore, _, mockIdPRepo, _, _, _ := setupLoginTest(t)
	defer ctrl.Finish()

	flowState := &domain.LoginFlowState{
		FlowID:    "valid-flow",
		ExpiresAt: time.Now().Add(10 * time.Minute),
	}
	mockFlowStore.EXPECT().GetFlow(gomock.Any(), "valid-flow").Return(flowState, nil)
	mockIdPRepo.EXPECT().ListIdPs(gomock.Any(), true).Return([]*domain.IdentityProvider{
		{Name: "google", IsEnabled: true},
	}, nil)

	// When
	req := httptest.NewRequest("GET", "/login", nil)
	req.AddCookie(&http.Cookie{Name: "sso_oidc_flow_id", Value: "valid-flow"})
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Then
	require.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "Sign in to your account")
}

func TestLoginSubmit_MissingFields(t *testing.T) {
	// Given
	router, ctrl, _, _, _, _, _, _ := setupLoginTest(t)
	defer ctrl.Finish()

	// When - POST with empty fields
	form := url.Values{}
	form.Set("csrf_token", "test-csrf")
	form.Set("email", "")
	form.Set("password", "")

	req := httptest.NewRequest("POST", "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: "sso_csrf_token", Value: "test-csrf"})
	req.AddCookie(&http.Cookie{Name: "sso_oidc_flow_id", Value: "valid-flow"})
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Then
	require.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "All fields are required")
}

func TestLoginSubmit_MissingCSRF(t *testing.T) {
	// Given
	router, ctrl, _, _, _, _, _, _ := setupLoginTest(t)
	defer ctrl.Finish()

	// When - POST without CSRF token
	form := url.Values{}
	form.Set("email", "test@example.com")
	form.Set("password", "password123")

	req := httptest.NewRequest("POST", "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: "sso_oidc_flow_id", Value: "valid-flow"})
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Then
	require.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "Invalid form submission")
}

func TestLoginSubmit_RateLimited(t *testing.T) {
	// Given
	router, ctrl, mockFlowStore, mockUserRepo, _, mockPasswordHasher, _, _ := setupLoginTest(t)
	defer ctrl.Finish()

	flowState := &domain.LoginFlowState{
		FlowID:    "valid-flow",
		ExpiresAt: time.Now().Add(10 * time.Minute),
	}
	mockFlowStore.EXPECT().GetFlow(gomock.Any(), "valid-flow").Return(flowState, nil).AnyTimes()

	user := &domain.User{
		ID:           "user-123",
		Email:        "test@example.com",
		PasswordHash: "hashed-password",
		Status:       domain.UserStatusActive,
	}
	mockUserRepo.EXPECT().GetUserByEmail(gomock.Any(), "test@example.com").Return(user, nil).AnyTimes()
	mockPasswordHasher.EXPECT().Verify("hashed-password", "wrong").Return(errors.New("mismatch")).AnyTimes()

	// When - Make multiple failed attempts to trigger rate limiting
	for i := 0; i < 5; i++ {
		form := url.Values{}
		form.Set("csrf_token", "test-csrf")
		form.Set("email", "test@example.com")
		form.Set("password", "wrong")

		req := httptest.NewRequest("POST", "/login", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.AddCookie(&http.Cookie{Name: "sso_csrf_token", Value: "test-csrf"})
		req.AddCookie(&http.Cookie{Name: "sso_oidc_flow_id", Value: "valid-flow"})
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
	}

	// Then - Next attempt should be rate limited
	form := url.Values{}
	form.Set("csrf_token", "test-csrf")
	form.Set("email", "test@example.com")
	form.Set("password", "password")

	req := httptest.NewRequest("POST", "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: "sso_csrf_token", Value: "test-csrf"})
	req.AddCookie(&http.Cookie{Name: "sso_oidc_flow_id", Value: "valid-flow"})
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "Too many attempts")
}

func TestLoginSubmit_UnknownEmail(t *testing.T) {
	// Given
	router, ctrl, mockFlowStore, mockUserRepo, _, _, _, _ := setupLoginTest(t)
	defer ctrl.Finish()

	flowState := &domain.LoginFlowState{
		FlowID:    "valid-flow",
		ExpiresAt: time.Now().Add(10 * time.Minute),
	}
	mockFlowStore.EXPECT().GetFlow(gomock.Any(), "valid-flow").Return(flowState, nil)
	mockUserRepo.EXPECT().GetUserByEmail(gomock.Any(), "unknown@example.com").Return(nil, errors.New("user not found"))

	// When
	form := url.Values{}
	form.Set("csrf_token", "test-csrf")
	form.Set("email", "unknown@example.com")
	form.Set("password", "password123")

	req := httptest.NewRequest("POST", "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: "sso_csrf_token", Value: "test-csrf"})
	req.AddCookie(&http.Cookie{Name: "sso_oidc_flow_id", Value: "valid-flow"})
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Then
	require.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "Invalid email or password")
}

func TestLoginSubmit_WrongPassword(t *testing.T) {
	// Given
	router, ctrl, mockFlowStore, mockUserRepo, _, mockPasswordHasher, _, _ := setupLoginTest(t)
	defer ctrl.Finish()

	flowState := &domain.LoginFlowState{
		FlowID:    "valid-flow",
		ExpiresAt: time.Now().Add(10 * time.Minute),
	}
	mockFlowStore.EXPECT().GetFlow(gomock.Any(), "valid-flow").Return(flowState, nil)

	user := &domain.User{
		ID:           "user-123",
		Email:        "test@example.com",
		PasswordHash: "hashed-password",
		Status:       domain.UserStatusActive,
	}
	mockUserRepo.EXPECT().GetUserByEmail(gomock.Any(), "test@example.com").Return(user, nil)
	mockPasswordHasher.EXPECT().Verify("hashed-password", "wrong-password").Return(bcrypt.ErrMismatchedHashAndPassword)

	// When
	form := url.Values{}
	form.Set("csrf_token", "test-csrf")
	form.Set("email", "test@example.com")
	form.Set("password", "wrong-password")

	req := httptest.NewRequest("POST", "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: "sso_csrf_token", Value: "test-csrf"})
	req.AddCookie(&http.Cookie{Name: "sso_oidc_flow_id", Value: "valid-flow"})
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Then
	require.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "Invalid email or password")
}

func TestLoginSubmit_Success(t *testing.T) {
	// Given
	router, ctrl, mockFlowStore, mockUserRepo, _, mockPasswordHasher, _, mockOAuthService := setupLoginTest(t)
	defer ctrl.Finish()

	flowState := &domain.LoginFlowState{
		FlowID:    "valid-flow",
		ExpiresAt: time.Now().Add(10 * time.Minute),
		ClientID:  "test-client",
	}
	mockFlowStore.EXPECT().GetFlow(gomock.Any(), "valid-flow").Return(flowState, nil)
	mockFlowStore.EXPECT().UpdateFlow(gomock.Any(), "valid-flow", gomock.Any()).Return(nil)

	user := &domain.User{
		ID:           "user-123",
		Email:        "test@example.com",
		PasswordHash: "hashed-password",
		Status:       domain.UserStatusActive,
		FirstName:    "Test",
		LastName:     "User",
	}
	mockUserRepo.EXPECT().GetUserByEmail(gomock.Any(), "test@example.com").Return(user, nil)
	mockPasswordHasher.EXPECT().Verify("hashed-password", "correct-password").Return(nil)
	mockOAuthService.EXPECT().ValidateClient(gomock.Any(), "test-client", "").Return(&domain.Client{
		ID:             "test-client",
		RequireConsent: false,
	}, nil)

	// When
	form := url.Values{}
	form.Set("csrf_token", "test-csrf")
	form.Set("email", "test@example.com")
	form.Set("password", "correct-password")

	req := httptest.NewRequest("POST", "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: "sso_csrf_token", Value: "test-csrf"})
	req.AddCookie(&http.Cookie{Name: "sso_oidc_flow_id", Value: "valid-flow"})
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Then
	require.Equal(t, http.StatusFound, w.Code)
	assert.Contains(t, w.Header().Get("Location"), "/oauth2/authorize")
}

func TestLoginSubmit_ExpiredFlow(t *testing.T) {
	// Given
	router, ctrl, mockFlowStore, _, _, _, _, _ := setupLoginTest(t)
	defer ctrl.Finish()

	flowState := &domain.LoginFlowState{
		FlowID:    "expired-flow",
		ExpiresAt: time.Now().Add(-10 * time.Minute), // Already expired
	}
	mockFlowStore.EXPECT().GetFlow(gomock.Any(), "expired-flow").Return(flowState, nil)
	mockFlowStore.EXPECT().DeleteFlow(gomock.Any(), "expired-flow").Return(nil)

	// When
	form := url.Values{}
	form.Set("csrf_token", "test-csrf")
	form.Set("email", "test@example.com")
	form.Set("password", "password")

	req := httptest.NewRequest("POST", "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: "sso_csrf_token", Value: "test-csrf"})
	req.AddCookie(&http.Cookie{Name: "sso_oidc_flow_id", Value: "expired-flow"})
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Then
	require.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "Login request has expired")
}

func TestLoginSubmit_InactiveAccount(t *testing.T) {
	// Given
	router, ctrl, mockFlowStore, mockUserRepo, _, mockPasswordHasher, _, _ := setupLoginTest(t)
	defer ctrl.Finish()

	flowState := &domain.LoginFlowState{
		FlowID:    "valid-flow",
		ExpiresAt: time.Now().Add(10 * time.Minute),
	}
	mockFlowStore.EXPECT().GetFlow(gomock.Any(), "valid-flow").Return(flowState, nil)

	user := &domain.User{
		ID:           "user-123",
		Email:        "locked@example.com",
		PasswordHash: "hashed-password",
		Status:       domain.UserStatusLocked,
	}
	mockUserRepo.EXPECT().GetUserByEmail(gomock.Any(), "locked@example.com").Return(user, nil)
	mockPasswordHasher.EXPECT().Verify("hashed-password", "password").Return(nil)

	// When
	form := url.Values{}
	form.Set("csrf_token", "test-csrf")
	form.Set("email", "locked@example.com")
	form.Set("password", "password")

	req := httptest.NewRequest("POST", "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: "sso_csrf_token", Value: "test-csrf"})
	req.AddCookie(&http.Cookie{Name: "sso_oidc_flow_id", Value: "valid-flow"})
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Then
	require.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "Account is not active")
}
