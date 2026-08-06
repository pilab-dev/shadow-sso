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
	totp2fa "github.com/pilab-dev/shadow-sso/internal/auth/totp"
	otptotp "github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

// setupMFATest wires the POST /mfa route with gomock-backed deps. It reuses the
// testReturnToCookieSecret const declared in login_returnto_test.go (same
// package) so signed sso_return_to cookies minted by signReturnToCookie verify.
func setupMFATest(t *testing.T) (
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
		UserRepo:        mockUserRepo,
		PasswordHasher:  mock_domain.NewMockPasswordHasher(ctrl),
		FlowStore:       mockFlowStore,
		Config:          webauth.DefaultConfig(),
		SSOCookieSecret: testReturnToCookieSecret,
	})

	router := gin.New()
	router.LoadHTMLGlob("templates/*.html")
	router.POST("/mfa", wa.MFASubmitHandler)

	return router, ctrl, mockFlowStore, mockUserRepo
}

// mfaTestSecret generates a fresh TOTP secret (base32 string) to store on the
// mocked user, mirroring how internal/auth/totp produces secrets.
func mfaTestSecret(t *testing.T) string {
	t.Helper()
	key, _, err := totp2fa.GenerateTOTPSecret("shadow-sso", "test@example.com")
	require.NoError(t, err)
	return key.Secret()
}

// mfaTestCode returns the current valid TOTP code for the given secret.
func mfaTestCode(t *testing.T, secret string) string {
	t.Helper()
	code, err := otptotp.GenerateCode(secret, time.Now())
	require.NoError(t, err)
	return code
}

// mfaRequest builds a POST /mfa request carrying the CSRF cookie + form token
// and any extra cookies (e.g. a signed sso_return_to cookie).
func mfaRequest(t *testing.T, flowID, csrf, code string, extra ...*http.Cookie) *http.Request {
	t.Helper()
	form := url.Values{}
	form.Set("csrf_token", csrf)
	form.Set("flow_id", flowID)
	form.Set("otp", code)

	req := httptest.NewRequest("POST", "/mfa", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: webauth.CSRFCookieName, Value: csrf})
	for _, c := range extra {
		req.AddCookie(c)
	}
	return req
}

// mfaFlowState returns a valid, in-date flow state with an authenticated user.
func mfaFlowState(flowID string) *domain.LoginFlowState {
	return &domain.LoginFlowState{
		FlowID:    flowID,
		ExpiresAt: time.Now().Add(15 * time.Minute),
		UserID:    "user-123",
	}
}

// TestMFASubmit_SyntheticFlowRedirectsToReturnTo: a ClientID-less (flow-less)
// flow with a signed sso_return_to cookie and a valid TOTP code redirects to
// the exact return_to path and clears the cookie.
func TestMFASubmit_SyntheticFlowRedirectsToReturnTo(t *testing.T) {
	// Given
	router, ctrl, mockFlowStore, mockUserRepo := setupMFATest(t)
	defer ctrl.Finish()

	wantReturnTo := "/oauth2/device/verify?user_code=ABCD-EFGH"
	flowState := mfaFlowState("mfa-flow")
	mockFlowStore.EXPECT().GetFlow(gomock.Any(), "mfa-flow").Return(flowState, nil)
	mockFlowStore.EXPECT().UpdateFlow(gomock.Any(), "mfa-flow", gomock.Any()).Return(nil)

	secret := mfaTestSecret(t)
	user := &domain.User{ID: "user-123", Email: "test@example.com", TwoFactorSecret: secret}
	mockUserRepo.EXPECT().GetUserByID(gomock.Any(), "user-123").Return(user, nil)

	// When
	req := mfaRequest(t, "mfa-flow", "test-csrf", mfaTestCode(t, secret),
		&http.Cookie{Name: webauth.ReturnToCookieName, Value: signReturnToCookie(t, wantReturnTo)})
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Then
	require.Equal(t, http.StatusFound, w.Code)
	assert.Equal(t, wantReturnTo, w.Header().Get("Location"))

	rtCookie := findCookie(w.Result().Cookies(), webauth.ReturnToCookieName)
	require.NotNil(t, rtCookie, "sso_return_to cookie must be cleared in the response")
	assert.Empty(t, rtCookie.Value)
	assert.LessOrEqual(t, rtCookie.MaxAge, 0)
}

// TestMFASubmit_SyntheticFlowWithoutReturnToCookie: a synthetic flow without a
// return_to cookie redirects to "/".
func TestMFASubmit_SyntheticFlowWithoutReturnToCookie(t *testing.T) {
	// Given
	router, ctrl, mockFlowStore, mockUserRepo := setupMFATest(t)
	defer ctrl.Finish()

	mockFlowStore.EXPECT().GetFlow(gomock.Any(), "mfa-flow").Return(mfaFlowState("mfa-flow"), nil)
	mockFlowStore.EXPECT().UpdateFlow(gomock.Any(), "mfa-flow", gomock.Any()).Return(nil)

	secret := mfaTestSecret(t)
	user := &domain.User{ID: "user-123", Email: "test@example.com", TwoFactorSecret: secret}
	mockUserRepo.EXPECT().GetUserByID(gomock.Any(), "user-123").Return(user, nil)

	// When
	req := mfaRequest(t, "mfa-flow", "test-csrf", mfaTestCode(t, secret))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Then
	require.Equal(t, http.StatusFound, w.Code)
	assert.Equal(t, "/", w.Header().Get("Location"))
}

// TestMFASubmit_RealOIDCFlowRedirectsToAuthorize: a real OIDC flow (ClientID
// set) with a valid TOTP code redirects to /oauth2/authorize?flow_id=<id>,
// exactly as the non-MFA completion path does.
func TestMFASubmit_RealOIDCFlowRedirectsToAuthorize(t *testing.T) {
	// Given
	router, ctrl, mockFlowStore, mockUserRepo := setupMFATest(t)
	defer ctrl.Finish()

	flowState := mfaFlowState("oidc-flow")
	flowState.ClientID = "sssoctl"
	flowState.RedirectURI = "http://localhost:8080/callback"
	mockFlowStore.EXPECT().GetFlow(gomock.Any(), "oidc-flow").Return(flowState, nil)
	mockFlowStore.EXPECT().UpdateFlow(gomock.Any(), "oidc-flow", gomock.Any()).Return(nil)

	secret := mfaTestSecret(t)
	user := &domain.User{ID: "user-123", Email: "test@example.com", TwoFactorSecret: secret}
	mockUserRepo.EXPECT().GetUserByID(gomock.Any(), "user-123").Return(user, nil)

	// When
	req := mfaRequest(t, "oidc-flow", "test-csrf", mfaTestCode(t, secret))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Then
	require.Equal(t, http.StatusFound, w.Code)
	assert.Equal(t, "/oauth2/authorize?flow_id=oidc-flow", w.Header().Get("Location"))
}

// TestMFASubmit_InvalidTOTPCode: a wrong code re-renders mfa.html (200) with an
// error message and does NOT redirect.
func TestMFASubmit_InvalidTOTPCode(t *testing.T) {
	// Given
	router, ctrl, mockFlowStore, mockUserRepo := setupMFATest(t)
	defer ctrl.Finish()

	mockFlowStore.EXPECT().GetFlow(gomock.Any(), "mfa-flow").Return(mfaFlowState("mfa-flow"), nil)

	secret := mfaTestSecret(t)
	user := &domain.User{ID: "user-123", Email: "test@example.com", TwoFactorSecret: secret}
	mockUserRepo.EXPECT().GetUserByID(gomock.Any(), "user-123").Return(user, nil)

	// When - submit a definitely-wrong code
	req := mfaRequest(t, "mfa-flow", "test-csrf", "000000")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Then
	require.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "Invalid verification code. Please try again.")
	assert.Empty(t, w.Header().Get("Location"), "invalid code must not redirect")
}

// TestMFASubmit_MissingCSRF: a POST without a CSRF cookie/token is rejected
// with 400.
func TestMFASubmit_MissingCSRF(t *testing.T) {
	// Given
	router, ctrl, _, _ := setupMFATest(t)
	defer ctrl.Finish()

	// When - no CSRF cookie at all
	form := url.Values{}
	form.Set("flow_id", "mfa-flow")
	form.Set("otp", "123456")
	req := httptest.NewRequest("POST", "/mfa", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Then
	require.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "Invalid or expired login request")
}

// TestMFASubmit_InvalidCSRF: a POST with a mismatched CSRF cookie/token is
// rejected with 400.
func TestMFASubmit_InvalidCSRF(t *testing.T) {
	// Given
	router, ctrl, _, _ := setupMFATest(t)
	defer ctrl.Finish()

	// When - cookie value differs from the form token
	form := url.Values{}
	form.Set("csrf_token", "expected-token")
	form.Set("flow_id", "mfa-flow")
	form.Set("otp", "123456")
	req := httptest.NewRequest("POST", "/mfa", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: webauth.CSRFCookieName, Value: "different-token"})
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Then
	require.Equal(t, http.StatusBadRequest, w.Code)
}

// TestMFASubmit_UnknownFlow: an unknown flow_id is rejected with 400.
func TestMFASubmit_UnknownFlow(t *testing.T) {
	// Given
	router, ctrl, mockFlowStore, _ := setupMFATest(t)
	defer ctrl.Finish()

	mockFlowStore.EXPECT().GetFlow(gomock.Any(), "unknown-flow").Return(nil, errors.New("flow not found"))

	// When
	req := mfaRequest(t, "unknown-flow", "test-csrf", "123456")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Then
	require.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "Invalid or expired login request")
}

// TestMFASubmit_ExpiredFlow: an expired flow is rejected with 400 and the flow
// is deleted best-effort.
func TestMFASubmit_ExpiredFlow(t *testing.T) {
	// Given
	router, ctrl, mockFlowStore, _ := setupMFATest(t)
	defer ctrl.Finish()

	flowState := mfaFlowState("expired-flow")
	flowState.ExpiresAt = time.Now().Add(-10 * time.Minute)
	mockFlowStore.EXPECT().GetFlow(gomock.Any(), "expired-flow").Return(flowState, nil)
	mockFlowStore.EXPECT().DeleteFlow(gomock.Any(), "expired-flow").Return(nil)

	// When
	req := mfaRequest(t, "expired-flow", "test-csrf", "123456")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Then
	require.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "Invalid or expired login request")
}

// TestMFASubmit_MissingFlowID: a POST without a flow_id is rejected with 400.
func TestMFASubmit_MissingFlowID(t *testing.T) {
	// Given
	router, ctrl, _, _ := setupMFATest(t)
	defer ctrl.Finish()

	// When
	req := mfaRequest(t, "", "test-csrf", "123456")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Then
	require.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "Invalid or expired login request")
}

// TestMFASubmit_NoUserIDInFlow: a valid flow without an authenticated user is
// rejected with 400 (login never completed the password step).
func TestMFASubmit_NoUserIDInFlow(t *testing.T) {
	// Given
	router, ctrl, mockFlowStore, _ := setupMFATest(t)
	defer ctrl.Finish()

	flowState := &domain.LoginFlowState{
		FlowID:    "mfa-flow",
		ExpiresAt: time.Now().Add(15 * time.Minute),
	}
	mockFlowStore.EXPECT().GetFlow(gomock.Any(), "mfa-flow").Return(flowState, nil)

	// When
	req := mfaRequest(t, "mfa-flow", "test-csrf", "123456")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Then
	require.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "Invalid or expired login request")
}
