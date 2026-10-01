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
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

const raSecret = "test-secret-32-bytes-long-for-hmac-sha256!!"

type raEnv struct {
	router *gin.Engine
	flows  *mock_domain.MockFlowStore
	users  *mock_domain.MockUserRepository
	hasher *mock_domain.MockPasswordHasher
}

func setupRequiredActionTest(t *testing.T) *raEnv {
	t.Helper()
	gin.SetMode(gin.TestMode)
	ctrl := gomock.NewController(t)
	e := &raEnv{
		flows:  mock_domain.NewMockFlowStore(ctrl),
		users:  mock_domain.NewMockUserRepository(ctrl),
		hasher: mock_domain.NewMockPasswordHasher(ctrl),
	}
	wa := webauth.New(&webauth.Options{
		UserRepo:        e.users,
		PasswordHasher:  e.hasher,
		FlowStore:       e.flows,
		Config:          webauth.DefaultConfig(),
		SSOCookieSecret: raSecret,
	})
	e.router = gin.New()
	e.router.LoadHTMLGlob("templates/*.html")
	e.router.POST("/login", wa.LoginSubmitHandler)
	e.router.GET("/required-action", wa.RequiredActionPageHandler)
	e.router.POST("/required-action", wa.RequiredActionSubmitHandler)
	return e
}

func raFlow(pending string) *domain.LoginFlowState {
	return &domain.LoginFlowState{
		FlowID:              "f1",
		ClientID:            "c1",
		UserID:              "u1",
		UserAuthenticatedAt: time.Now(),
		ExpiresAt:           time.Now().Add(10 * time.Minute),
		Pending:             pending,
	}
}

func raPost(path string, form url.Values) *http.Request {
	form.Set("csrf_token", "csrf")
	req := httptest.NewRequest("POST", path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: "sso_csrf_token", Value: "csrf"})
	return req
}

func hasCookie(w *httptest.ResponseRecorder, name string) bool {
	for _, c := range w.Result().Cookies() {
		if c.Name == name && c.Value != "" {
			return true
		}
	}
	return false
}

func TestLogin_UpdatePasswordParksFlowWithoutSSOCookie(t *testing.T) {
	e := setupRequiredActionTest(t)
	flow := raFlow("")
	flow.UserID, flow.UserAuthenticatedAt = "", time.Time{}
	e.flows.EXPECT().GetFlow(gomock.Any(), "f1").Return(flow, nil)
	user := &domain.User{ID: "u1", Email: "a@b.c", PasswordHash: "h", Status: domain.UserStatusActive,
		RequiredActions: []string{domain.RequiredActionUpdatePassword}}
	e.users.EXPECT().GetUserByEmail(gomock.Any(), "a@b.c").Return(user, nil)
	e.hasher.EXPECT().Verify("h", "pw").Return(nil)
	var saved *domain.LoginFlowState
	e.flows.EXPECT().UpdateFlow(gomock.Any(), "f1", gomock.Any()).DoAndReturn(
		func(_ any, _ string, s *domain.LoginFlowState) error { saved = s; return nil })

	req := raPost("/login", url.Values{"email": {"a@b.c"}, "password": {"pw"}})
	req.AddCookie(&http.Cookie{Name: "sso_oidc_flow_id", Value: "f1"})
	w := httptest.NewRecorder()
	e.router.ServeHTTP(w, req)

	require.Equal(t, http.StatusFound, w.Code)
	assert.Equal(t, "/required-action?flow_id=f1", w.Header().Get("Location"))
	require.NotNil(t, saved)
	assert.Equal(t, "action:UPDATE_PASSWORD", saved.Pending)
	assert.False(t, hasCookie(w, "sso_session"), "SSO cookie must not be issued before required actions complete")
}

func TestLogin_MFAMarksFlowPending(t *testing.T) {
	e := setupRequiredActionTest(t)
	flow := raFlow("")
	flow.UserID, flow.UserAuthenticatedAt = "", time.Time{}
	e.flows.EXPECT().GetFlow(gomock.Any(), "f1").Return(flow, nil)
	user := &domain.User{ID: "u1", Email: "a@b.c", PasswordHash: "h", Status: domain.UserStatusActive, IsTwoFactorEnabled: true}
	e.users.EXPECT().GetUserByEmail(gomock.Any(), "a@b.c").Return(user, nil)
	e.hasher.EXPECT().Verify("h", "pw").Return(nil)
	var saved *domain.LoginFlowState
	e.flows.EXPECT().UpdateFlow(gomock.Any(), "f1", gomock.Any()).DoAndReturn(
		func(_ any, _ string, s *domain.LoginFlowState) error { saved = s; return nil })

	req := raPost("/login", url.Values{"email": {"a@b.c"}, "password": {"pw"}})
	req.AddCookie(&http.Cookie{Name: "sso_oidc_flow_id", Value: "f1"})
	w := httptest.NewRecorder()
	e.router.ServeHTTP(w, req)

	require.NotNil(t, saved)
	assert.Equal(t, domain.FlowPendingMFA, saved.Pending, "password-only login must leave the flow MFA-pending")
	assert.False(t, saved.Authenticated())
	assert.False(t, hasCookie(w, "sso_session"))
}

func TestRequiredAction_RejectsFlowsNotParkedOnAnAction(t *testing.T) {
	for name, pending := range map[string]string{"mfa pending": domain.FlowPendingMFA, "nothing pending": ""} {
		t.Run(name, func(t *testing.T) {
			e := setupRequiredActionTest(t)
			e.flows.EXPECT().GetFlow(gomock.Any(), "f1").Return(raFlow(pending), nil)
			w := httptest.NewRecorder()
			e.router.ServeHTTP(w, httptest.NewRequest("GET", "/required-action?flow_id=f1", nil))
			assert.Equal(t, http.StatusBadRequest, w.Code)
		})
	}
	t.Run("unknown flow", func(t *testing.T) {
		e := setupRequiredActionTest(t)
		e.flows.EXPECT().GetFlow(gomock.Any(), "f1").Return(nil, errors.New("nope"))
		w := httptest.NewRecorder()
		e.router.ServeHTTP(w, httptest.NewRequest("GET", "/required-action?flow_id=f1", nil))
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

func TestRequiredAction_UpdatePasswordRenders(t *testing.T) {
	e := setupRequiredActionTest(t)
	e.flows.EXPECT().GetFlow(gomock.Any(), "f1").Return(raFlow("action:UPDATE_PASSWORD"), nil)
	e.users.EXPECT().GetUserByID(gomock.Any(), "u1").Return(&domain.User{ID: "u1", Status: domain.UserStatusActive}, nil)
	w := httptest.NewRecorder()
	e.router.ServeHTTP(w, httptest.NewRequest("GET", "/required-action?flow_id=f1", nil))
	require.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "Update your password")
}

func TestRequiredAction_UpdatePasswordValidation(t *testing.T) {
	cases := map[string]url.Values{
		"mismatch":  {"new_password": {"Sup3rSecret!"}, "confirm_password": {"different"}},
		"too short": {"new_password": {"abc"}, "confirm_password": {"abc"}},
	}
	for name, form := range cases {
		t.Run(name, func(t *testing.T) {
			e := setupRequiredActionTest(t)
			e.flows.EXPECT().GetFlow(gomock.Any(), "f1").Return(raFlow("action:UPDATE_PASSWORD"), nil)
			e.users.EXPECT().GetUserByID(gomock.Any(), "u1").Return(&domain.User{ID: "u1", Status: domain.UserStatusActive}, nil)
			form.Set("flow_id", "f1")
			w := httptest.NewRecorder()
			e.router.ServeHTTP(w, raPost("/required-action", form))
			assert.Equal(t, http.StatusUnprocessableEntity, w.Code)
			assert.False(t, hasCookie(w, "sso_session"))
		})
	}
}

func TestRequiredAction_UpdatePasswordRejectsReuse(t *testing.T) {
	e := setupRequiredActionTest(t)
	e.flows.EXPECT().GetFlow(gomock.Any(), "f1").Return(raFlow("action:UPDATE_PASSWORD"), nil)
	e.users.EXPECT().GetUserByID(gomock.Any(), "u1").Return(&domain.User{ID: "u1", PasswordHash: "old", Status: domain.UserStatusActive}, nil)
	e.hasher.EXPECT().Verify("old", "Sup3rSecret!").Return(nil) // same as current
	w := httptest.NewRecorder()
	e.router.ServeHTTP(w, raPost("/required-action", url.Values{"flow_id": {"f1"}, "new_password": {"Sup3rSecret!"}, "confirm_password": {"Sup3rSecret!"}}))
	assert.Equal(t, http.StatusUnprocessableEntity, w.Code)
}

func TestRequiredAction_UpdatePasswordCompletesLogin(t *testing.T) {
	e := setupRequiredActionTest(t)
	e.flows.EXPECT().GetFlow(gomock.Any(), "f1").Return(raFlow("action:UPDATE_PASSWORD"), nil)
	user := &domain.User{ID: "u1", Email: "a@b.c", PasswordHash: "old", Status: domain.UserStatusActive,
		RequiredActions: []string{domain.RequiredActionUpdatePassword}}
	e.users.EXPECT().GetUserByID(gomock.Any(), "u1").Return(user, nil)
	e.hasher.EXPECT().Verify("old", "Sup3rSecret!").Return(errors.New("mismatch"))
	e.hasher.EXPECT().Hash("Sup3rSecret!").Return("new-hash", nil)
	var persisted *domain.User
	e.users.EXPECT().UpdateUser(gomock.Any(), gomock.Any()).DoAndReturn(
		func(_ any, u *domain.User) error { persisted = u; return nil })
	var saved *domain.LoginFlowState
	e.flows.EXPECT().UpdateFlow(gomock.Any(), "f1", gomock.Any()).DoAndReturn(
		func(_ any, _ string, s *domain.LoginFlowState) error { saved = s; return nil })

	w := httptest.NewRecorder()
	e.router.ServeHTTP(w, raPost("/required-action", url.Values{"flow_id": {"f1"}, "new_password": {"Sup3rSecret!"}, "confirm_password": {"Sup3rSecret!"}}))

	require.Equal(t, http.StatusFound, w.Code)
	assert.Equal(t, "/oauth2/authorize?flow_id=f1", w.Header().Get("Location"))
	require.NotNil(t, persisted)
	assert.Equal(t, "new-hash", persisted.PasswordHash)
	assert.Empty(t, persisted.RequiredActions)
	require.NotNil(t, saved)
	assert.True(t, saved.Authenticated(), "pending marker must be cleared once the action is done")
	assert.True(t, hasCookie(w, "sso_session"), "SSO cookie is issued only after the action completes")
}

func TestRequiredAction_RequiresCSRF(t *testing.T) {
	e := setupRequiredActionTest(t)
	req := httptest.NewRequest("POST", "/required-action", strings.NewReader("flow_id=f1&new_password=x&confirm_password=x"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	e.router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}
