package webauth_test

import (
	"context"
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
	"github.com/pilab-dev/shadow-sso/internal/ssosession"
	services_mocks "github.com/pilab-dev/shadow-sso/services/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

const accountTestSecret = "account-chooser-secret-32-bytes-long!!"

type accountTestEnv struct {
	router       *gin.Engine
	ctrl         *gomock.Controller
	flowStore    *mock_domain.MockFlowStore
	userRepo     *mock_domain.MockUserRepository
	idpRepo      *mock_domain.MockIdPRepository
	hasher       *mock_domain.MockPasswordHasher
	oauthService *services_mocks.MockOAuthService
	sessionStore *oidcflow.InMemoryUserSessionStore
}

func setupAccountTest(t *testing.T) *accountTestEnv {
	t.Helper()
	gin.SetMode(gin.TestMode)
	ctrl := gomock.NewController(t)

	env := &accountTestEnv{
		ctrl:         ctrl,
		flowStore:    mock_domain.NewMockFlowStore(ctrl),
		userRepo:     mock_domain.NewMockUserRepository(ctrl),
		idpRepo:      mock_domain.NewMockIdPRepository(ctrl),
		hasher:       mock_domain.NewMockPasswordHasher(ctrl),
		oauthService: services_mocks.NewMockOAuthService(ctrl),
		sessionStore: oidcflow.NewInMemoryUserSessionStore(),
	}

	wa := webauth.New(&webauth.Options{
		UserRepo:          env.userRepo,
		PasswordHasher:    env.hasher,
		FlowStore:         env.flowStore,
		UserSessionStore:  env.sessionStore,
		IdPRepository:     env.idpRepo,
		FederationService: services_mocks.NewMockFederationService(ctrl),
		OAuthService:      env.oauthService,
		TokenService:      services_mocks.NewMockTokenService(ctrl),
		ClientService:     services_mocks.NewMockClientService(ctrl),
		Config:            webauth.DefaultConfig(),
		SSOCookieSecret:   accountTestSecret,
	})

	env.router = gin.New()
	env.router.LoadHTMLGlob("templates/*.html")
	env.router.GET("/login", wa.LoginPageHandler)
	env.router.POST("/login", wa.LoginSubmitHandler)
	env.router.POST("/login/select", wa.SelectAccountHandler)
	return env
}

func accountSessionCookie(t *testing.T, accounts ...ssosession.Account) *http.Cookie {
	t.Helper()
	rec := httptest.NewRecorder()
	require.NoError(t, ssosession.SetCookie(rec, &ssosession.Session{
		SessionID: ssosession.NewID(),
		Accounts:  accounts,
	}, false, accountTestSecret))
	cookies := rec.Result().Cookies()
	require.Len(t, cookies, 1)
	return cookies[0]
}

func opSessionCookie(t *testing.T, store domain.UserSessionStore, userID string) *http.Cookie {
	t.Helper()
	session := &domain.UserSession{
		SessionID:       "op-" + userID,
		UserID:          userID,
		AuthenticatedAt: time.Now().Add(-time.Minute),
		ExpiresAt:       time.Now().Add(time.Hour),
	}
	require.NoError(t, store.StoreUserSession(context.Background(), session))
	return &http.Cookie{Name: ssosession.OPSessionCookieName, Value: session.SessionID}
}

func accountPickerFlow() *domain.LoginFlowState {
	return &domain.LoginFlowState{
		FlowID:    "flow-1",
		ClientID:  "client-1",
		ExpiresAt: time.Now().Add(10 * time.Minute),
	}
}

func TestLoginPage_ShowsAccountChooser(t *testing.T) {
	env := setupAccountTest(t)
	defer env.ctrl.Finish()

	env.flowStore.EXPECT().GetFlow(gomock.Any(), "flow-1").Return(accountPickerFlow(), nil)
	env.idpRepo.EXPECT().ListIdPs(gomock.Any(), true).Return(nil, nil)

	req := httptest.NewRequest("GET", "/login", nil)
	req.AddCookie(&http.Cookie{Name: "sso_oidc_flow_id", Value: "flow-1"})
	req.AddCookie(accountSessionCookie(t, ssosession.Account{
		UserID:   "user-1",
		Email:    "user@example.com",
		Name:     "Test User",
		LastUsed: time.Now(),
	}))
	req.AddCookie(opSessionCookie(t, env.sessionStore, "user-1"))
	w := httptest.NewRecorder()
	env.router.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	body := w.Body.String()
	assert.Contains(t, body, "Choose an account")
	assert.Contains(t, body, "Test User")
	assert.Contains(t, body, "user@example.com")
	assert.Contains(t, body, "Current session")
	assert.Contains(t, body, "Use another account")
	assert.NotContains(t, body, "Sign in to your account")
}

func TestLoginPage_FormForcesCredentialForm(t *testing.T) {
	env := setupAccountTest(t)
	defer env.ctrl.Finish()

	env.flowStore.EXPECT().GetFlow(gomock.Any(), "flow-1").Return(accountPickerFlow(), nil)
	env.idpRepo.EXPECT().ListIdPs(gomock.Any(), true).Return(nil, nil)

	req := httptest.NewRequest("GET", "/login?form=1&email=user%40example.com", nil)
	req.AddCookie(&http.Cookie{Name: "sso_oidc_flow_id", Value: "flow-1"})
	req.AddCookie(accountSessionCookie(t, ssosession.Account{
		UserID:   "user-1",
		Email:    "user@example.com",
		Name:     "Test User",
		LastUsed: time.Now(),
	}))
	w := httptest.NewRecorder()
	env.router.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	body := w.Body.String()
	assert.Contains(t, body, "Sign in to your account")
	assert.Contains(t, body, `value="user@example.com"`)
	assert.Contains(t, body, "Use another account")
	assert.NotContains(t, body, "Choose an account")
}

func TestSelectAccount_CurrentOPSessionCompletesFlow(t *testing.T) {
	env := setupAccountTest(t)
	defer env.ctrl.Finish()

	env.flowStore.EXPECT().GetFlow(gomock.Any(), "flow-1").Return(accountPickerFlow(), nil)
	env.flowStore.EXPECT().UpdateFlow(gomock.Any(), "flow-1", gomock.Any()).DoAndReturn(
		func(_ context.Context, _ string, state *domain.LoginFlowState) error {
			require.Equal(t, "user-1", state.UserID)
			return nil
		},
	)
	env.oauthService.EXPECT().ValidateClient(gomock.Any(), "client-1", "").Return(&domain.Client{
		ID: "client-1",
	}, nil)

	form := url.Values{"csrf_token": {"test-csrf"}, "user_id": {"user-1"}}
	req := httptest.NewRequest("POST", "/login/select", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: webauth.CSRFCookieName, Value: "test-csrf"})
	req.AddCookie(&http.Cookie{Name: "sso_oidc_flow_id", Value: "flow-1"})
	req.AddCookie(accountSessionCookie(t, ssosession.Account{
		UserID:   "user-1",
		Email:    "user@example.com",
		Name:     "Test User",
		LastUsed: time.Now(),
	}))
	req.AddCookie(opSessionCookie(t, env.sessionStore, "user-1"))
	w := httptest.NewRecorder()
	env.router.ServeHTTP(w, req)

	require.Equal(t, http.StatusFound, w.Code)
	assert.Equal(t, "/oauth2/authorize?flow_id=flow-1", w.Header().Get("Location"))
}

func TestSelectAccount_RequiresPasswordForOtherAccount(t *testing.T) {
	env := setupAccountTest(t)
	defer env.ctrl.Finish()

	env.flowStore.EXPECT().GetFlow(gomock.Any(), "flow-1").Return(accountPickerFlow(), nil)

	form := url.Values{"csrf_token": {"test-csrf"}, "user_id": {"user-1"}}
	req := httptest.NewRequest("POST", "/login/select", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: webauth.CSRFCookieName, Value: "test-csrf"})
	req.AddCookie(&http.Cookie{Name: "sso_oidc_flow_id", Value: "flow-1"})
	req.AddCookie(accountSessionCookie(t, ssosession.Account{
		UserID:   "user-1",
		Email:    "user@example.com",
		Name:     "Test User",
		LastUsed: time.Now(),
	}))
	w := httptest.NewRecorder()
	env.router.ServeHTTP(w, req)

	require.Equal(t, http.StatusFound, w.Code)
	assert.Equal(t, "/login?form=1&email=user%40example.com", w.Header().Get("Location"))
}

func TestSelectAccount_PromptLoginAlwaysRequiresPassword(t *testing.T) {
	env := setupAccountTest(t)
	defer env.ctrl.Finish()

	flow := accountPickerFlow()
	flow.Prompt = "login"
	env.flowStore.EXPECT().GetFlow(gomock.Any(), "flow-1").Return(flow, nil)

	form := url.Values{"csrf_token": {"test-csrf"}, "user_id": {"user-1"}}
	req := httptest.NewRequest("POST", "/login/select", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: webauth.CSRFCookieName, Value: "test-csrf"})
	req.AddCookie(&http.Cookie{Name: "sso_oidc_flow_id", Value: "flow-1"})
	req.AddCookie(accountSessionCookie(t, ssosession.Account{
		UserID:   "user-1",
		Email:    "user@example.com",
		Name:     "Test User",
		LastUsed: time.Now(),
	}))
	req.AddCookie(opSessionCookie(t, env.sessionStore, "user-1"))
	w := httptest.NewRecorder()
	env.router.ServeHTTP(w, req)

	require.Equal(t, http.StatusFound, w.Code)
	assert.Equal(t, "/login?form=1&email=user%40example.com", w.Header().Get("Location"))
}

func TestLoginSubmit_MergesAccountHistory(t *testing.T) {
	env := setupAccountTest(t)
	defer env.ctrl.Finish()

	env.flowStore.EXPECT().GetFlow(gomock.Any(), "flow-1").Return(accountPickerFlow(), nil)
	env.flowStore.EXPECT().UpdateFlow(gomock.Any(), "flow-1", gomock.Any()).Return(nil)
	env.userRepo.EXPECT().GetUserByEmail(gomock.Any(), "new@example.com").Return(&domain.User{
		ID:           "user-new",
		Email:        "new@example.com",
		PasswordHash: "hashed",
		Status:       domain.UserStatusActive,
		FirstName:    "New",
		LastName:     "User",
	}, nil)
	env.hasher.EXPECT().Verify("hashed", "password").Return(nil)
	env.oauthService.EXPECT().ValidateClient(gomock.Any(), "client-1", "").Return(&domain.Client{
		ID: "client-1",
	}, nil)

	form := url.Values{
		"csrf_token": {"test-csrf"},
		"email":      {"new@example.com"},
		"password":   {"password"},
	}
	req := httptest.NewRequest("POST", "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: webauth.CSRFCookieName, Value: "test-csrf"})
	req.AddCookie(&http.Cookie{Name: "sso_oidc_flow_id", Value: "flow-1"})
	req.AddCookie(accountSessionCookie(t, ssosession.Account{
		UserID:   "user-old",
		Email:    "old@example.com",
		Name:     "Old User",
		LastUsed: time.Now().Add(-time.Hour),
	}))
	w := httptest.NewRecorder()
	env.router.ServeHTTP(w, req)

	require.Equal(t, http.StatusFound, w.Code)
	assert.Equal(t, "/oauth2/authorize?flow_id=flow-1", w.Header().Get("Location"))

	var sessionCookie *http.Cookie
	for _, cookie := range w.Result().Cookies() {
		if cookie.Name == ssosession.CookieName {
			sessionCookie = cookie
		}
	}
	require.NotNil(t, sessionCookie)

	session, err := ssosession.VerifyAndDecode(sessionCookie.Value, accountTestSecret)
	require.NoError(t, err)
	require.Len(t, session.Accounts, 2)
	assert.Equal(t, "user-new", session.Accounts[0].UserID)
	assert.Equal(t, "user-old", session.Accounts[1].UserID)
}
