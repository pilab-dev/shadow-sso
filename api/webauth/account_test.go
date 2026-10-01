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
	"github.com/pilab-dev/shadow-sso/internal/ssosession"
	services_mocks "github.com/pilab-dev/shadow-sso/services/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

type acctEnv struct {
	router   *gin.Engine
	users    *mock_domain.MockUserRepository
	hasher   *mock_domain.MockPasswordHasher
	sessions *mock_domain.MockSessionRepository
	fed      *services_mocks.MockFederationService
	cookie   *http.Cookie
}

func setupAccountTest(t *testing.T) *acctEnv {
	t.Helper()
	gin.SetMode(gin.TestMode)
	ctrl := gomock.NewController(t)
	e := &acctEnv{
		users:    mock_domain.NewMockUserRepository(ctrl),
		hasher:   mock_domain.NewMockPasswordHasher(ctrl),
		sessions: mock_domain.NewMockSessionRepository(ctrl),
		fed:      services_mocks.NewMockFederationService(ctrl),
	}
	wa := webauth.New(&webauth.Options{
		UserRepo:          e.users,
		PasswordHasher:    e.hasher,
		FlowStore:         mock_domain.NewMockFlowStore(ctrl),
		FederationService: e.fed,
		SessionRepo:       e.sessions,
		Config:            webauth.DefaultConfig(),
		SSOCookieSecret:   raSecret,
	})
	e.router = gin.New()
	e.router.LoadHTMLGlob("templates/*.html")
	e.router.GET("/account", wa.AccountOverviewHandler())
	e.router.POST("/account/profile", wa.AccountProfileSubmitHandler())
	e.router.GET("/account/security", wa.AccountSecurityHandler())
	e.router.POST("/account/password", wa.AccountPasswordSubmitHandler())
	e.router.POST("/account/mfa/disable", wa.AccountMFADisableSubmitHandler())
	e.router.GET("/account/sessions", wa.AccountSessionsHandler())
	e.router.POST("/account/sessions/revoke", wa.AccountSessionRevokeHandler())
	e.router.GET("/account/linked", wa.AccountLinkedHandler())
	e.router.POST("/account/linked/unlink", wa.AccountUnlinkSubmitHandler())

	// A valid signed sso_session cookie for user u1.
	rec := httptest.NewRecorder()
	require.NoError(t, webauth.SetSSOSessionCookie(rec, &ssosession.Session{
		SessionID: "s",
		Accounts:  []ssosession.Account{{UserID: "u1", Email: "a@b.c", LastUsed: time.Now()}},
	}, false, raSecret))
	e.cookie = rec.Result().Cookies()[0]
	return e
}

func (e *acctEnv) user(u *domain.User) { e.users.EXPECT().GetUserByID(gomock.Any(), "u1").Return(u, nil).AnyTimes() }

func (e *acctEnv) get(path string) *httptest.ResponseRecorder {
	req := httptest.NewRequest("GET", path, nil)
	req.AddCookie(e.cookie)
	w := httptest.NewRecorder()
	e.router.ServeHTTP(w, req)
	return w
}

func (e *acctEnv) post(path string, form url.Values) *httptest.ResponseRecorder {
	req := raPost(path, form)
	req.AddCookie(e.cookie)
	w := httptest.NewRecorder()
	e.router.ServeHTTP(w, req)
	return w
}

func activeUser() *domain.User {
	return &domain.User{ID: "u1", Email: "a@b.c", FirstName: "Ann", PasswordHash: "old", Status: domain.UserStatusActive}
}

func TestAccount_RequiresSignIn(t *testing.T) {
	e := setupAccountTest(t)
	w := httptest.NewRecorder()
	e.router.ServeHTTP(w, httptest.NewRequest("GET", "/account/security", nil))
	require.Equal(t, http.StatusFound, w.Code)
	assert.Equal(t, "/login?return_to=%2Faccount%2Fsecurity", w.Header().Get("Location"))

	// A forged cookie is not accepted.
	req := httptest.NewRequest("GET", "/account", nil)
	req.AddCookie(&http.Cookie{Name: "sso_session", Value: "eyJ4IjoxfQ.forged"})
	w = httptest.NewRecorder()
	e.router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusFound, w.Code)
	assert.Contains(t, w.Header().Get("Location"), "/login")
}

func TestAccount_OverviewAndProfile(t *testing.T) {
	e := setupAccountTest(t)
	u := activeUser()
	e.user(u)

	w := e.get("/account")
	require.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "a@b.c")
	assert.Equal(t, "no-store", w.Header().Get("Cache-Control"))

	e.users.EXPECT().UpdateUser(gomock.Any(), gomock.Any()).Return(nil)
	w = e.post("/account/profile", url.Values{"first_name": {" Bob "}, "last_name": {"Lee"}})
	require.Equal(t, http.StatusSeeOther, w.Code)
	assert.Equal(t, "/account?ok=profile_saved", w.Header().Get("Location"))
	assert.Equal(t, "Bob", u.FirstName)
}

func TestAccount_PostsRequireCSRF(t *testing.T) {
	e := setupAccountTest(t)
	e.user(activeUser())
	req := httptest.NewRequest("POST", "/account/profile", nil)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(e.cookie)
	w := httptest.NewRecorder()
	e.router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestAccount_ChangePassword(t *testing.T) {
	good := url.Values{"current_password": {"old-pw"}, "new_password": {"Sup3rSecret!"}, "confirm_password": {"Sup3rSecret!"}}

	t.Run("wrong current password is rejected", func(t *testing.T) {
		e := setupAccountTest(t)
		e.user(activeUser())
		e.hasher.EXPECT().Verify("old", "old-pw").Return(assert.AnError)
		w := e.post("/account/password", good)
		assert.Equal(t, http.StatusUnprocessableEntity, w.Code)
	})

	t.Run("succeeds and revokes other sessions", func(t *testing.T) {
		e := setupAccountTest(t)
		u := activeUser()
		e.user(u)
		e.hasher.EXPECT().Verify("old", "old-pw").Return(nil)
		e.hasher.EXPECT().Verify("old", "Sup3rSecret!").Return(assert.AnError)
		e.hasher.EXPECT().Hash("Sup3rSecret!").Return("new-hash", nil)
		e.users.EXPECT().UpdateUser(gomock.Any(), gomock.Any()).Return(nil)
		e.sessions.EXPECT().DeleteSessionsByUserID(gomock.Any(), "u1").Return(int64(2), nil)

		w := e.post("/account/password", good)
		require.Equal(t, http.StatusSeeOther, w.Code)
		assert.Equal(t, "/account/security?ok=password_changed", w.Header().Get("Location"))
		assert.Equal(t, "new-hash", u.PasswordHash)
	})

	t.Run("policy and mismatch", func(t *testing.T) {
		e := setupAccountTest(t)
		e.user(activeUser())
		e.hasher.EXPECT().Verify("old", "old-pw").Return(nil).Times(2)
		w := e.post("/account/password", url.Values{"current_password": {"old-pw"}, "new_password": {"abc"}, "confirm_password": {"abc"}})
		assert.Equal(t, http.StatusUnprocessableEntity, w.Code)
		w = e.post("/account/password", url.Values{"current_password": {"old-pw"}, "new_password": {"Sup3rSecret!"}, "confirm_password": {"nope"}})
		assert.Equal(t, http.StatusUnprocessableEntity, w.Code)
	})
}

func TestAccount_DisableMFARequiresStepUp(t *testing.T) {
	e := setupAccountTest(t)
	u := activeUser()
	u.IsTwoFactorEnabled, u.TwoFactorMethod, u.TwoFactorSecret = true, "TOTP", "SECRET"
	e.user(u)

	e.hasher.EXPECT().Verify("old", "wrong").Return(assert.AnError)
	w := e.post("/account/mfa/disable", url.Values{"current_password": {"wrong"}})
	assert.Equal(t, http.StatusUnprocessableEntity, w.Code)
	assert.True(t, u.IsTwoFactorEnabled, "MFA must stay on without a valid confirmation")

	e.hasher.EXPECT().Verify("old", "right").Return(nil)
	e.users.EXPECT().UpdateUser(gomock.Any(), gomock.Any()).Return(nil)
	w = e.post("/account/mfa/disable", url.Values{"current_password": {"right"}})
	require.Equal(t, http.StatusSeeOther, w.Code)
	assert.False(t, u.IsTwoFactorEnabled)
	assert.Empty(t, u.TwoFactorSecret)
}

func TestAccount_SessionsListAndOwnershipOnRevoke(t *testing.T) {
	e := setupAccountTest(t)
	e.user(activeUser())
	e.sessions.EXPECT().ListSessionsByUserID(gomock.Any(), "u1", gomock.Any()).Return([]*domain.Session{
		{ID: "sess1", UserID: "u1", ClientID: "app", IPAddress: "1.2.3.4", LastUsedAt: time.Now()},
		{ID: "revoked", UserID: "u1", IsRevoked: true},
	}, nil)
	w := e.get("/account/sessions")
	require.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "1.2.3.4")
	assert.NotContains(t, w.Body.String(), `value="revoked"`)

	// Revoking someone else's session is a silent no-op.
	e.sessions.EXPECT().GetSessionByID(gomock.Any(), "theirs").Return(&domain.Session{ID: "theirs", UserID: "other"}, nil)
	w = e.post("/account/sessions/revoke", url.Values{"session_id": {"theirs"}})
	assert.Equal(t, http.StatusSeeOther, w.Code)

	e.sessions.EXPECT().GetSessionByID(gomock.Any(), "sess1").Return(&domain.Session{ID: "sess1", UserID: "u1"}, nil)
	e.sessions.EXPECT().DeleteSession(gomock.Any(), "sess1").Return(nil)
	w = e.post("/account/sessions/revoke", url.Values{"session_id": {"sess1"}})
	assert.Equal(t, http.StatusSeeOther, w.Code)
}

func TestAccount_CannotUnlinkOnlySignInMethod(t *testing.T) {
	e := setupAccountTest(t)
	u := activeUser()
	u.PasswordHash = "" // social-only account
	e.user(u)
	e.fed.EXPECT().ListUserFederatedIdentities(gomock.Any(), "u1").Return([]*domain.UserFederatedIdentity{
		{ProviderID: "google", ProviderUserID: "g1", ProviderEmail: "a@b.c"}}, nil).AnyTimes()

	w := e.post("/account/linked/unlink", url.Values{"provider": {"google"}, "provider_user_id": {"g1"}})
	assert.Equal(t, http.StatusUnprocessableEntity, w.Code)
	assert.Contains(t, w.Body.String(), "Set a password")
}
