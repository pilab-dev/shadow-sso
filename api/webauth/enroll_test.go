package webauth_test

import (
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
	"github.com/pilab-dev/shadow-sso/internal/oidcflow"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func setupMFAEnrollTest(t *testing.T) (
	*gin.Engine,
	*gomock.Controller,
	*mock_domain.MockFlowStore,
	*mock_domain.MockUserRepository,
) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	ctrl := gomock.NewController(t)

	mockFlowStore := mock_domain.NewMockFlowStore(ctrl)
	mockUserRepo := mock_domain.NewMockUserRepository(ctrl)

	wa := webauth.New(&webauth.Options{
		UserRepo:         mockUserRepo,
		PasswordHasher:   mock_domain.NewMockPasswordHasher(ctrl),
		FlowStore:        mockFlowStore,
		UserSessionStore: oidcflow.NewInMemoryUserSessionStore(),
		Config:           webauth.DefaultConfig(),
		SSOCookieSecret:  testReturnToCookieSecret,
	})

	router := gin.New()
	router.LoadHTMLGlob("templates/*.html")
	router.GET("/mfa/enroll", wa.MFAEnrollPageHandler)
	router.POST("/mfa/enroll", wa.MFAEnrollSubmitHandler)
	router.POST("/mfa/enroll/complete", wa.MFAEnrollCompleteHandler)

	return router, ctrl, mockFlowStore, mockUserRepo
}

func enrollRequest(t *testing.T, path, flowID, code string) *http.Request {
	t.Helper()
	form := url.Values{}
	form.Set("csrf_token", "test-csrf")
	form.Set("flow_id", flowID)
	if code != "" {
		form.Set("code", code)
	}
	req := httptest.NewRequest("POST", path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: webauth.CSRFCookieName, Value: "test-csrf"})
	return req
}

func TestMFAEnroll_ForcedUserEnrollsAndCompletesLogin(t *testing.T) {
	router, ctrl, mockFlowStore, mockUserRepo := setupMFAEnrollTest(t)
	defer ctrl.Finish()

	flowState := &domain.LoginFlowState{
		FlowID:    "enroll-flow",
		ExpiresAt: time.Now().Add(15 * time.Minute),
		UserID:    "user-1",
	}
	user := &domain.User{
		ID:          "user-1",
		Email:       "user@example.com",
		Status:      domain.UserStatusActive,
		MFARequired: true,
	}
	mockFlowStore.EXPECT().GetFlow(gomock.Any(), "enroll-flow").Return(flowState, nil).AnyTimes()
	mockFlowStore.EXPECT().UpdateFlow(gomock.Any(), "enroll-flow", gomock.Any()).Return(nil).AnyTimes()
	mockUserRepo.EXPECT().GetUserByID(gomock.Any(), "user-1").Return(user, nil).AnyTimes()
	mockUserRepo.EXPECT().UpdateUser(gomock.Any(), gomock.Any()).Return(nil).AnyTimes()

	// 1. Enrollment page generates and stores a pending secret.
	req := httptest.NewRequest("GET", "/mfa/enroll?flow_id=enroll-flow", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	assert.Contains(t, w.Body.String(), "Set up two-factor authentication")
	require.NotEmpty(t, user.TwoFactorSecret)
	assert.Equal(t, "TOTP", user.TwoFactorMethod)
	assert.False(t, user.IsTwoFactorEnabled)

	// 2. A valid code enables 2FA and shows recovery codes exactly once.
	req = enrollRequest(t, "/mfa/enroll", "enroll-flow", mfaTestCode(t, user.TwoFactorSecret))
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	assert.Contains(t, w.Body.String(), "Save your recovery codes")
	assert.True(t, user.IsTwoFactorEnabled)
	assert.Len(t, user.TwoFactorRecoveryCodes, 10)
	assert.True(t, flowState.MFAEnrollmentVerified)

	// 3. Completion establishes the session and clears the one-shot marker.
	req = enrollRequest(t, "/mfa/enroll/complete", "enroll-flow", "")
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	require.Equal(t, http.StatusFound, w.Code, w.Body.String())
	assert.Equal(t, "/", w.Header().Get("Location"))
	assert.False(t, flowState.MFAEnrollmentVerified)
}

func TestMFAEnroll_InvalidCodeDoesNotEnable(t *testing.T) {
	router, ctrl, mockFlowStore, mockUserRepo := setupMFAEnrollTest(t)
	defer ctrl.Finish()

	flowState := &domain.LoginFlowState{
		FlowID:    "enroll-flow",
		ExpiresAt: time.Now().Add(15 * time.Minute),
		UserID:    "user-1",
	}
	user := &domain.User{ID: "user-1", Email: "user@example.com", MFARequired: true}
	mockFlowStore.EXPECT().GetFlow(gomock.Any(), "enroll-flow").Return(flowState, nil).AnyTimes()
	mockUserRepo.EXPECT().GetUserByID(gomock.Any(), "user-1").Return(user, nil).AnyTimes()
	mockUserRepo.EXPECT().UpdateUser(gomock.Any(), gomock.Any()).Return(nil).AnyTimes()

	req := httptest.NewRequest("GET", "/mfa/enroll?flow_id=enroll-flow", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)

	req = enrollRequest(t, "/mfa/enroll", "enroll-flow", "000000")
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "Invalid verification code")
	assert.False(t, user.IsTwoFactorEnabled)
	assert.Empty(t, user.TwoFactorRecoveryCodes)
	assert.False(t, flowState.MFAEnrollmentVerified)
}

// TestMFAEnroll_CompleteWithoutVerifiedCeremonyRejected guards against a
// password-only session completing the flow by calling the completion handler
// directly.
func TestMFAEnroll_CompleteWithoutVerifiedCeremonyRejected(t *testing.T) {
	router, ctrl, mockFlowStore, _ := setupMFAEnrollTest(t)
	defer ctrl.Finish()

	flowState := &domain.LoginFlowState{
		FlowID:    "enroll-flow",
		ExpiresAt: time.Now().Add(15 * time.Minute),
		UserID:    "user-1",
	}
	mockFlowStore.EXPECT().GetFlow(gomock.Any(), "enroll-flow").Return(flowState, nil)

	req := enrollRequest(t, "/mfa/enroll/complete", "enroll-flow", "")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusForbidden, w.Code)
	assert.Contains(t, w.Body.String(), "Enrollment has not been verified")
}

func TestLoginSubmit_ForcedMFAWithoutFactorRedirectsToEnrollment(t *testing.T) {
	router, ctrl, mockFlowStore, mockUserRepo, _, mockPasswordHasher, _, _ := setupLoginTest(t)
	defer ctrl.Finish()

	flowState := &domain.LoginFlowState{
		FlowID:    "valid-flow",
		ExpiresAt: time.Now().Add(10 * time.Minute),
	}
	mockFlowStore.EXPECT().GetFlow(gomock.Any(), "valid-flow").Return(flowState, nil)
	mockFlowStore.EXPECT().UpdateFlow(gomock.Any(), "valid-flow", gomock.Any()).Return(nil)

	user := &domain.User{
		ID:           "user-1",
		Email:        "user@example.com",
		PasswordHash: "hashed",
		Status:       domain.UserStatusActive,
		MFARequired:  true,
	}
	mockUserRepo.EXPECT().GetUserByEmail(gomock.Any(), "user@example.com").Return(user, nil)
	mockPasswordHasher.EXPECT().Verify("hashed", "password").Return(nil)

	form := url.Values{}
	form.Set("csrf_token", "test-csrf")
	form.Set("email", "user@example.com")
	form.Set("password", "password")
	req := httptest.NewRequest("POST", "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: webauth.CSRFCookieName, Value: "test-csrf"})
	req.AddCookie(&http.Cookie{Name: "sso_oidc_flow_id", Value: "valid-flow"})
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusFound, w.Code)
	assert.Equal(t, "/mfa/enroll?flow_id=valid-flow", w.Header().Get("Location"))
}

func TestLoginSubmit_UnverifiableFactorRejected(t *testing.T) {
	router, ctrl, mockFlowStore, mockUserRepo, _, mockPasswordHasher, _, _ := setupLoginTest(t)
	defer ctrl.Finish()

	flowState := &domain.LoginFlowState{
		FlowID:    "valid-flow",
		ExpiresAt: time.Now().Add(10 * time.Minute),
	}
	mockFlowStore.EXPECT().GetFlow(gomock.Any(), "valid-flow").Return(flowState, nil)

	// Email MFA sets the aggregate flag the login runner reads, but the /mfa
	// page only verifies TOTP and there is no secret.
	user := &domain.User{
		ID:                 "user-1",
		Email:              "user@example.com",
		PasswordHash:       "hashed",
		Status:             domain.UserStatusActive,
		IsTwoFactorEnabled: true,
		TwoFactorMethod:    "EMAIL",
		EmailMFAEnabled:    true,
	}
	mockUserRepo.EXPECT().GetUserByEmail(gomock.Any(), "user@example.com").Return(user, nil)
	mockPasswordHasher.EXPECT().Verify("hashed", "password").Return(nil)

	form := url.Values{}
	form.Set("csrf_token", "test-csrf")
	form.Set("email", "user@example.com")
	form.Set("password", "password")
	req := httptest.NewRequest("POST", "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: webauth.CSRFCookieName, Value: "test-csrf"})
	req.AddCookie(&http.Cookie{Name: "sso_oidc_flow_id", Value: "valid-flow"})
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusForbidden, w.Code)
	assert.Contains(t, w.Body.String(), "cannot verify")
}
