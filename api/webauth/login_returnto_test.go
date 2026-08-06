package webauth_test

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/pilab-dev/shadow-sso/domain"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

// testReturnToCookieSecret mirrors the SSOCookieSecret configured in
// setupLoginTest so the tests can mint validly-signed sso_return_to cookies.
const testReturnToCookieSecret = "test-secret-32-bytes-long-for-hmac-sha256!!"

func signReturnToCookie(t *testing.T, returnTo string) string {
	t.Helper()
	payload := base64.RawURLEncoding.EncodeToString([]byte(returnTo))
	mac := hmac.New(sha256.New, []byte(testReturnToCookieSecret))
	mac.Write([]byte(returnTo))
	signature := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return payload + "." + signature
}

func findCookie(cookies []*http.Cookie, name string) *http.Cookie {
	for _, c := range cookies {
		if c.Name == name {
			return c
		}
	}
	return nil
}

// TestLoginPage_FlowlessWithReturnTo: GET /login?return_to=... without a flow
// cookie renders the login page (200, not 400), stores a synthetic flow, and
// sets both the flow cookie and the signed return_to cookie.
func TestLoginPage_FlowlessWithReturnTo(t *testing.T) {
	// Given
	router, ctrl, mockFlowStore, _, mockIdPRepo, _, _, _ := setupLoginTest(t)
	defer ctrl.Finish()

	wantReturnTo := "/oauth2/device/verify?user_code=ABCD-EFGH"
	var storedFlowID string
	mockFlowStore.EXPECT().StoreFlow(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
		func(_ context.Context, flowID string, _ domain.LoginFlowState) error {
			storedFlowID = flowID
			return nil
		},
	).Times(1)
	mockIdPRepo.EXPECT().ListIdPs(gomock.Any(), true).Return([]*domain.IdentityProvider{}, nil)

	// When
	req := httptest.NewRequest("GET", "/login?return_to="+url.QueryEscape(wantReturnTo), nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Then
	require.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "Sign in to your account")
	require.NotEmpty(t, storedFlowID)

	cookies := w.Result().Cookies()
	flowCookie := findCookie(cookies, "sso_oidc_flow_id")
	require.NotNil(t, flowCookie)
	assert.Equal(t, storedFlowID, flowCookie.Value)
	assert.True(t, flowCookie.HttpOnly)
	assert.Equal(t, http.SameSiteLaxMode, flowCookie.SameSite)

	rtCookie := findCookie(cookies, "sso_return_to")
	require.NotNil(t, rtCookie)
	assert.True(t, rtCookie.HttpOnly)
	assert.Equal(t, http.SameSiteLaxMode, rtCookie.SameSite)
	parts := strings.Split(rtCookie.Value, ".")
	require.Len(t, parts, 2)
	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	require.NoError(t, err)
	assert.Equal(t, wantReturnTo, string(payload))
}

// TestLoginSubmit_FlowlessHappyPath: full POST with a synthetic (ClientID-less)
// flow redirects to the exact signed return_to path and clears the cookie.
func TestLoginSubmit_FlowlessHappyPath(t *testing.T) {
	// Given
	router, ctrl, mockFlowStore, mockUserRepo, _, mockPasswordHasher, _, _ := setupLoginTest(t)
	defer ctrl.Finish()

	wantReturnTo := "/oauth2/device/verify?user_code=ABCD-EFGH"
	flowState := &domain.LoginFlowState{
		FlowID:    "synthetic-flow",
		ExpiresAt: time.Now().Add(15 * time.Minute),
	}
	mockFlowStore.EXPECT().GetFlow(gomock.Any(), "synthetic-flow").Return(flowState, nil)
	mockFlowStore.EXPECT().UpdateFlow(gomock.Any(), "synthetic-flow", gomock.Any()).Return(nil)

	user := &domain.User{
		ID:           "user-123",
		Email:        "test@example.com",
		PasswordHash: "hashed-password",
		Status:       domain.UserStatusActive,
	}
	mockUserRepo.EXPECT().GetUserByEmail(gomock.Any(), "test@example.com").Return(user, nil)
	mockPasswordHasher.EXPECT().Verify("hashed-password", "correct-password").Return(nil)

	// When
	form := url.Values{}
	form.Set("csrf_token", "test-csrf")
	form.Set("email", "test@example.com")
	form.Set("password", "correct-password")

	req := httptest.NewRequest("POST", "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: "sso_csrf_token", Value: "test-csrf"})
	req.AddCookie(&http.Cookie{Name: "sso_oidc_flow_id", Value: "synthetic-flow"})
	req.AddCookie(&http.Cookie{Name: "sso_return_to", Value: signReturnToCookie(t, wantReturnTo)})
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Then
	require.Equal(t, http.StatusFound, w.Code)
	assert.Equal(t, wantReturnTo, w.Header().Get("Location"))

	rtCookie := findCookie(w.Result().Cookies(), "sso_return_to")
	require.NotNil(t, rtCookie, "sso_return_to cookie must be cleared in the response")
	assert.Empty(t, rtCookie.Value)
	assert.LessOrEqual(t, rtCookie.MaxAge, 0)
}

// TestLoginPage_FlowlessInvalidReturnTo: GET /login?return_to=<evil> falls back
// to the existing 400 error page and sets no flow/return_to cookies.
func TestLoginPage_FlowlessInvalidReturnTo(t *testing.T) {
	evils := []string{"//evil.com", "https://evil.com", "/../etc", `\evil`}
	for _, evil := range evils {
		t.Run(evil, func(t *testing.T) {
			// Given
			router, ctrl, _, _, _, _, _, _ := setupLoginTest(t)
			defer ctrl.Finish()

			// When
			req := httptest.NewRequest("GET", "/login?return_to="+url.QueryEscape(evil), nil)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			// Then
			require.Equal(t, http.StatusBadRequest, w.Code)
			assert.Contains(t, w.Body.String(), "Missing login request identifier")
			for _, c := range w.Result().Cookies() {
				assert.NotEqual(t, "sso_oidc_flow_id", c.Name)
				assert.NotEqual(t, "sso_return_to", c.Name)
			}
		})
	}
}

// TestLoginSubmit_FlowlessInvalidReturnToCookie: a signed-but-invalid
// sso_return_to cookie value (would be an open redirect) redirects to "/"
// instead of the evil destination.
func TestLoginSubmit_FlowlessInvalidReturnToCookie(t *testing.T) {
	evils := []string{"//evil.com", "https://evil.com", "/../etc", `\evil`}
	for _, evil := range evils {
		t.Run(evil, func(t *testing.T) {
			// Given
			router, ctrl, mockFlowStore, mockUserRepo, _, mockPasswordHasher, _, _ := setupLoginTest(t)
			defer ctrl.Finish()

			flowState := &domain.LoginFlowState{
				FlowID:    "synthetic-flow",
				ExpiresAt: time.Now().Add(15 * time.Minute),
			}
			mockFlowStore.EXPECT().GetFlow(gomock.Any(), "synthetic-flow").Return(flowState, nil)
			mockFlowStore.EXPECT().UpdateFlow(gomock.Any(), "synthetic-flow", gomock.Any()).Return(nil)

			user := &domain.User{
				ID:           "user-123",
				Email:        "test@example.com",
				PasswordHash: "hashed-password",
				Status:       domain.UserStatusActive,
			}
			mockUserRepo.EXPECT().GetUserByEmail(gomock.Any(), "test@example.com").Return(user, nil)
			mockPasswordHasher.EXPECT().Verify("hashed-password", "correct-password").Return(nil)

			// When
			form := url.Values{}
			form.Set("csrf_token", "test-csrf")
			form.Set("email", "test@example.com")
			form.Set("password", "correct-password")

			req := httptest.NewRequest("POST", "/login", strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.AddCookie(&http.Cookie{Name: "sso_csrf_token", Value: "test-csrf"})
			req.AddCookie(&http.Cookie{Name: "sso_oidc_flow_id", Value: "synthetic-flow"})
			req.AddCookie(&http.Cookie{Name: "sso_return_to", Value: signReturnToCookie(t, evil)})
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			// Then
			require.Equal(t, http.StatusFound, w.Code)
			assert.Equal(t, "/", w.Header().Get("Location"))
		})
	}
}

// TestLoginSubmit_FlowlessWithoutReturnToCookie: a synthetic flow without a
// return_to cookie redirects to "/".
func TestLoginSubmit_FlowlessWithoutReturnToCookie(t *testing.T) {
	// Given
	router, ctrl, mockFlowStore, mockUserRepo, _, mockPasswordHasher, _, _ := setupLoginTest(t)
	defer ctrl.Finish()

	flowState := &domain.LoginFlowState{
		FlowID:    "synthetic-flow",
		ExpiresAt: time.Now().Add(15 * time.Minute),
	}
	mockFlowStore.EXPECT().GetFlow(gomock.Any(), "synthetic-flow").Return(flowState, nil)
	mockFlowStore.EXPECT().UpdateFlow(gomock.Any(), "synthetic-flow", gomock.Any()).Return(nil)

	user := &domain.User{
		ID:           "user-123",
		Email:        "test@example.com",
		PasswordHash: "hashed-password",
		Status:       domain.UserStatusActive,
	}
	mockUserRepo.EXPECT().GetUserByEmail(gomock.Any(), "test@example.com").Return(user, nil)
	mockPasswordHasher.EXPECT().Verify("hashed-password", "correct-password").Return(nil)

	// When
	form := url.Values{}
	form.Set("csrf_token", "test-csrf")
	form.Set("email", "test@example.com")
	form.Set("password", "correct-password")

	req := httptest.NewRequest("POST", "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: "sso_csrf_token", Value: "test-csrf"})
	req.AddCookie(&http.Cookie{Name: "sso_oidc_flow_id", Value: "synthetic-flow"})
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Then
	require.Equal(t, http.StatusFound, w.Code)
	assert.Equal(t, "/", w.Header().Get("Location"))
}
