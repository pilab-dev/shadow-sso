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
	"github.com/pilab-dev/shadow-sso/internal/ssosession"
	services_mocks "github.com/pilab-dev/shadow-sso/services/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

const (
	deviceTestSSOCookieSecret = "test-secret-32-bytes-long-for-hmac-sha256!!"
	testCSRFToken       = "test-csrf-token"
)

// setupDeviceTest wires the device verification routes with gomock-backed deps.
func setupDeviceTest(t *testing.T) (
	*gin.Engine,
	*gomock.Controller,
	*mock_domain.MockDeviceAuthorizationRepository,
	*services_mocks.MockOAuthService,
	*services_mocks.MockClientService,
) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	ctrl := gomock.NewController(t)

	mockDeviceAuthRepo := mock_domain.NewMockDeviceAuthorizationRepository(ctrl)
	mockOAuthService := services_mocks.NewMockOAuthService(ctrl)
	mockClientService := services_mocks.NewMockClientService(ctrl)

	wa := webauth.New(&webauth.Options{
		OAuthService:    mockOAuthService,
		ClientService:   mockClientService,
		DeviceAuthRepo:  mockDeviceAuthRepo,
		Config:          webauth.DefaultConfig(),
		SSOCookieSecret: deviceTestSSOCookieSecret,
	})

	router := gin.New()
	router.LoadHTMLGlob("templates/*.html")
	router.GET("/oauth2/device/verify", wa.DeviceVerificationPageHandler)
	router.POST("/oauth2/device/verify", wa.DeviceVerificationSubmitHandler)

	return router, ctrl, mockDeviceAuthRepo, mockOAuthService, mockClientService
}

// authenticatedSessionCookie builds a valid signed sso_session cookie for the
// given user, mirroring what a completed login would set.
func authenticatedSessionCookie(t *testing.T, userID string) *http.Cookie {
	t.Helper()
	rec := httptest.NewRecorder()
	session := &ssosession.Session{
		SessionID: ssosession.NewID(),
		Accounts: []ssosession.Account{{
			UserID:   userID,
			Email:    "user@example.com",
			Name:     "Test User",
			LastUsed: time.Now(),
		}},
	}
	require.NoError(t, webauth.SetSSOSessionCookie(rec, session, false, deviceTestSSOCookieSecret))
	for _, c := range rec.Result().Cookies() {
		if c.Name == ssosession.CookieName {
			return c
		}
	}
	t.Fatal("expected sso_session cookie to be set")
	return nil
}

// authenticatedRequest returns a GET request carrying the signed session and a
// matching CSRF cookie so both session auth and form CSRF are satisfied.
func authenticatedRequest(t *testing.T, method, path string, form url.Values) *http.Request {
	t.Helper()
	var req *http.Request
	if form != nil {
		req = httptest.NewRequest(method, path, strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	} else {
		req = httptest.NewRequest(method, path, nil)
	}
	req.AddCookie(authenticatedSessionCookie(t, "user-1"))
	req.AddCookie(&http.Cookie{Name: webauth.CSRFCookieName, Value: testCSRFToken})
	return req
}

func TestDeviceVerifyPage_UnauthenticatedRedirectsToLogin(t *testing.T) {
	// Given an unauthenticated request with a user code
	router, ctrl, _, _, _ := setupDeviceTest(t)
	defer ctrl.Finish()

	// When the verification page is requested
	req := httptest.NewRequest("GET", "/oauth2/device/verify?user_code=ABCD-EFGH", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Then the user is redirected to /login with the return_to preserving the code
	require.Equal(t, http.StatusFound, w.Code)
	loc := w.Header().Get("Location")
	assert.True(t, strings.HasPrefix(loc, "/login?return_to="), "Location = %q", loc)
	unescaped, err := url.QueryUnescape(strings.TrimPrefix(loc, "/login?return_to="))
	require.NoError(t, err)
	assert.Equal(t, "/oauth2/device/verify?user_code=ABCD-EFGH", unescaped)
}

func TestDeviceVerifyPage_UnauthenticatedWithoutCodeRedirectsToPlainVerify(t *testing.T) {
	// Given an unauthenticated request without a user code
	router, ctrl, _, _, _ := setupDeviceTest(t)
	defer ctrl.Finish()

	// When the verification page is requested
	req := httptest.NewRequest("GET", "/oauth2/device/verify", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Then the user is redirected to /login with a plain verify return_to
	require.Equal(t, http.StatusFound, w.Code)
	loc := w.Header().Get("Location")
	assert.True(t, strings.HasPrefix(loc, "/login?return_to="), "Location = %q", loc)
	unescaped, err := url.QueryUnescape(strings.TrimPrefix(loc, "/login?return_to="))
	require.NoError(t, err)
	assert.Equal(t, "/oauth2/device/verify", unescaped)
}

func TestDeviceVerifyPage_AuthenticatedWithValidCode(t *testing.T) {
	// Given an authenticated user and a pending device code for a known client
	router, ctrl, mockDeviceAuthRepo, _, mockClientService := setupDeviceTest(t)
	defer ctrl.Finish()

	mockDeviceAuthRepo.EXPECT().GetDeviceAuthByUserCode(gomock.Any(), "ABCD-EFGH").Return(
		&domain.DeviceCode{DeviceCode: "dev-123", UserCode: "ABCD-EFGH", ClientID: "sssoctl", Status: domain.DeviceCodeStatusPending},
		nil,
	)
	mockClientService.EXPECT().GetClient(gomock.Any(), "sssoctl").Return(&domain.Client{Name: "ssoctl CLI"}, nil)

	// When the verification page is requested with the code
	req := authenticatedRequest(t, "GET", "/oauth2/device/verify?user_code=ABCD-EFGH", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Then the page shows the code and the requesting application
	require.Equal(t, http.StatusOK, w.Code)
	body := w.Body.String()
	assert.Contains(t, body, "ABCD-EFGH")
	assert.Contains(t, body, "ssoctl CLI")
	assert.Contains(t, body, "Approve")
	assert.Contains(t, body, "Deny")
}

func TestDeviceVerifyPage_AuthenticatedWithoutCode(t *testing.T) {
	// Given an authenticated user with no user code prefilled
	router, ctrl, _, _, _ := setupDeviceTest(t)
	defer ctrl.Finish()

	// When the verification page is requested without a code
	req := authenticatedRequest(t, "GET", "/oauth2/device/verify", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Then the page renders with an empty code entry field and no crash
	require.Equal(t, http.StatusOK, w.Code)
	body := w.Body.String()
	assert.Contains(t, body, `name="user_code"`)
	assert.Contains(t, body, "Activate Device")
}

func TestDeviceVerifyPage_UnknownCodeShowsErrorState(t *testing.T) {
	// Given an authenticated user and a code that does not exist
	router, ctrl, mockDeviceAuthRepo, _, _ := setupDeviceTest(t)
	defer ctrl.Finish()

	mockDeviceAuthRepo.EXPECT().GetDeviceAuthByUserCode(gomock.Any(), "GHIJ-KLMN").Return(nil, domain.ErrUserCodeNotFound)

	// When the verification page is requested with the unknown code
	req := authenticatedRequest(t, "GET", "/oauth2/device/verify?user_code=GHIJ-KLMN", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Then the page renders an error state without panicking
	require.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "Invalid or expired code")
}

func TestDeviceVerifySubmit_ApproveSuccess(t *testing.T) {
	// Given an authenticated user and a valid pending code
	router, ctrl, _, mockOAuthService, _ := setupDeviceTest(t)
	defer ctrl.Finish()

	mockOAuthService.EXPECT().VerifyUserCode(gomock.Any(), "ABCD-EFGH", "user-1").Return(
		&domain.DeviceCode{DeviceCode: "dev-123", UserCode: "ABCD-EFGH", Status: domain.DeviceCodeStatusAuthorized},
		nil,
	)

	// When the user approves the code
	form := url.Values{"user_code": {"ABCD-EFGH"}, "action": {"approve"}, "csrf_token": {testCSRFToken}}
	req := authenticatedRequest(t, "POST", "/oauth2/device/verify", form)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Then the page confirms activation
	require.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "Device activated successfully")
}

func TestDeviceVerifySubmit_ApproveInvalidCode(t *testing.T) {
	// Given an authenticated user and a code the service cannot find
	router, ctrl, _, mockOAuthService, _ := setupDeviceTest(t)
	defer ctrl.Finish()

	mockOAuthService.EXPECT().VerifyUserCode(gomock.Any(), "BAD-CODE", "user-1").Return(nil, domain.ErrUserCodeNotFound)

	// When the user submits the invalid code
	form := url.Values{"user_code": {"BAD-CODE"}, "action": {"approve"}, "csrf_token": {testCSRFToken}}
	req := authenticatedRequest(t, "POST", "/oauth2/device/verify", form)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Then the page shows the mapped error message
	require.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "Invalid or expired code")
}

func TestDeviceVerifySubmit_Deny(t *testing.T) {
	// Given an authenticated user and a pending device code
	router, ctrl, mockDeviceAuthRepo, _, _ := setupDeviceTest(t)
	defer ctrl.Finish()

	mockDeviceAuthRepo.EXPECT().GetDeviceAuthByUserCode(gomock.Any(), "ABCD-EFGH").Return(
		&domain.DeviceCode{DeviceCode: "dev-123", UserCode: "ABCD-EFGH", ClientID: "sssoctl"},
		nil,
	)
	mockDeviceAuthRepo.EXPECT().UpdateDeviceAuthStatus(gomock.Any(), "dev-123", domain.DeviceCodeStatusDenied).Return(nil)

	// When the user denies the code
	form := url.Values{"user_code": {"ABCD-EFGH"}, "action": {"deny"}, "csrf_token": {testCSRFToken}}
	req := authenticatedRequest(t, "POST", "/oauth2/device/verify", form)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Then the code is marked denied and the page confirms it
	require.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "Device access denied.")
}

func TestDeviceVerifySubmit_MissingCSRFRejected(t *testing.T) {
	// Given an authenticated user but no CSRF token
	router, ctrl, _, _, _ := setupDeviceTest(t)
	defer ctrl.Finish()

	// When a POST arrives without the CSRF token
	form := url.Values{"user_code": {"ABCD-EFGH"}, "action": {"approve"}}
	req := httptest.NewRequest("POST", "/oauth2/device/verify", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(authenticatedSessionCookie(t, "user-1"))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Then the submission is rejected with 400
	require.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "Invalid form submission")
}

func TestDeviceVerifySubmit_InvalidCSRFRejected(t *testing.T) {
	// Given an authenticated user and a mismatched CSRF token
	router, ctrl, _, _, _ := setupDeviceTest(t)
	defer ctrl.Finish()

	// When a POST arrives with a wrong CSRF token
	form := url.Values{"user_code": {"ABCD-EFGH"}, "action": {"approve"}, "csrf_token": {"wrong-token"}}
	req := authenticatedRequest(t, "POST", "/oauth2/device/verify", form)
	req.AddCookie(&http.Cookie{Name: webauth.CSRFCookieName, Value: "other-token"})
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Then the submission is rejected with 400
	require.Equal(t, http.StatusBadRequest, w.Code)
}
