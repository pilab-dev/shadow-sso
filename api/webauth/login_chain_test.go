package webauth_test

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/pilab-dev/shadow-sso/api/webauth"
	"github.com/pilab-dev/shadow-sso/domain"
	mock_domain "github.com/pilab-dev/shadow-sso/domain/mocks"
	authtotp "github.com/pilab-dev/shadow-sso/internal/auth/totp"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

// TestLoginChain_PasswordThenMFAThenRequiredActionThenAuthorize drives the real handlers through a
// stateful flow store: at no intermediate step may the flow be authenticated or an SSO cookie issued.
func TestLoginChain_PasswordThenMFAThenRequiredActionThenAuthorize(t *testing.T) {
	gin.SetMode(gin.TestMode)
	ctrl := gomock.NewController(t)

	key, _, err := authtotp.GenerateTOTPSecret("Shadow SSO", "a@b.c")
	require.NoError(t, err)
	user := &domain.User{ID: "u1", Email: "a@b.c", PasswordHash: "old", Status: domain.UserStatusActive,
		IsTwoFactorEnabled: true, TwoFactorMethod: "TOTP", TwoFactorSecret: key.Secret(),
		RequiredActions: []string{domain.RequiredActionUpdatePassword}}

	flow := &domain.LoginFlowState{FlowID: "f1", ClientID: "c1", ExpiresAt: time.Now().Add(10 * time.Minute)}
	flows := mock_domain.NewMockFlowStore(ctrl)
	flows.EXPECT().GetFlow(gomock.Any(), "f1").DoAndReturn(func(_ any, _ string) (*domain.LoginFlowState, error) {
		cp := *flow
		return &cp, nil
	}).AnyTimes()
	flows.EXPECT().UpdateFlow(gomock.Any(), "f1", gomock.Any()).DoAndReturn(func(_ any, _ string, s *domain.LoginFlowState) error {
		cp := *s
		flow = &cp
		return nil
	}).AnyTimes()

	users := mock_domain.NewMockUserRepository(ctrl)
	users.EXPECT().GetUserByEmail(gomock.Any(), "a@b.c").Return(user, nil).AnyTimes()
	users.EXPECT().GetUserByID(gomock.Any(), "u1").Return(user, nil).AnyTimes()
	users.EXPECT().UpdateUser(gomock.Any(), gomock.Any()).Return(nil).AnyTimes()
	hasher := mock_domain.NewMockPasswordHasher(ctrl)
	hasher.EXPECT().Verify("old", "pw").Return(nil).AnyTimes()
	hasher.EXPECT().Verify("old", "Sup3rSecret!").Return(assert.AnError).AnyTimes()
	hasher.EXPECT().Hash("Sup3rSecret!").Return("new-hash", nil).AnyTimes()

	wa := webauth.New(&webauth.Options{
		UserRepo: users, PasswordHasher: hasher, FlowStore: flows,
		Config: webauth.DefaultConfig(), SSOCookieSecret: raSecret,
	})
	router := gin.New()
	router.LoadHTMLGlob("templates/*.html")
	router.POST("/login", wa.LoginSubmitHandler)
	router.POST("/mfa", wa.MFASubmitHandler)
	router.GET("/required-action", wa.RequiredActionPageHandler)
	router.POST("/required-action", wa.RequiredActionSubmitHandler)

	do := func(req *http.Request) *httptest.ResponseRecorder {
		req.AddCookie(&http.Cookie{Name: "sso_oidc_flow_id", Value: "f1"})
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		return w
	}

	// 1. Password only: MFA page, flow parked on MFA, no SSO cookie.
	w := do(raPost("/login", url.Values{"email": {"a@b.c"}, "password": {"pw"}}))
	require.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "Two-Factor Authentication")
	assert.Equal(t, domain.FlowPendingMFA, flow.Pending)
	assert.False(t, flow.Authenticated())
	assert.False(t, hasCookie(w, "sso_session"))

	// The required-action page must not be reachable while MFA is outstanding.
	assert.Equal(t, http.StatusBadRequest, do(httptest.NewRequest("GET", "/required-action?flow_id=f1", nil)).Code)

	// 2. Valid TOTP: parked on the required action, still no cookie, still unauthenticated.
	code, err := totp.GenerateCode(key.Secret(), time.Now())
	require.NoError(t, err)
	w = do(raPost("/mfa", url.Values{"flow_id": {"f1"}, "otp": {code}}))
	require.Equal(t, http.StatusFound, w.Code)
	assert.Equal(t, "/required-action?flow_id=f1", w.Header().Get("Location"))
	assert.Equal(t, "action:UPDATE_PASSWORD", flow.Pending)
	assert.False(t, flow.Authenticated())
	assert.False(t, hasCookie(w, "sso_session"))

	// 3. Required action done: flow authenticated, cookie issued, back into authorize.
	w = do(raPost("/required-action", url.Values{"flow_id": {"f1"}, "new_password": {"Sup3rSecret!"}, "confirm_password": {"Sup3rSecret!"}}))
	require.Equal(t, http.StatusFound, w.Code)
	assert.Equal(t, "/oauth2/authorize?flow_id=f1", w.Header().Get("Location"))
	assert.True(t, flow.Authenticated())
	assert.True(t, hasCookie(w, "sso_session"))
	assert.Equal(t, "new-hash", user.PasswordHash)
	assert.Empty(t, user.RequiredActions)
}
