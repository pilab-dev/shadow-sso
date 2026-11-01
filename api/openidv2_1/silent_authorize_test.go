package openidv2_1_test

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	sssoapi "github.com/pilab-dev/shadow-sso/api"
	sssogin "github.com/pilab-dev/shadow-sso/api/openidv2_1"
	"github.com/pilab-dev/shadow-sso/api/webauth"
	"github.com/pilab-dev/shadow-sso/domain"
	mock_domain "github.com/pilab-dev/shadow-sso/domain/mocks"
	services_mocks "github.com/pilab-dev/shadow-sso/services/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

type silentAuthorizeTestEnv struct {
	router       *gin.Engine
	clientSvc    *services_mocks.MockClientService
	oauthSvc     *services_mocks.MockOAuthService
	sessionStore *mock_domain.MockUserSessionStore
}

func setupSilentAuthorizeTest(t *testing.T) *silentAuthorizeTestEnv {
	t.Helper()
	gin.SetMode(gin.TestMode)
	ctrl := gomock.NewController(t)

	env := &silentAuthorizeTestEnv{
		clientSvc:    services_mocks.NewMockClientService(ctrl),
		oauthSvc:     services_mocks.NewMockOAuthService(ctrl),
		sessionStore: mock_domain.NewMockUserSessionStore(ctrl),
	}

	api := sssogin.NewOAuth2API(&sssogin.OAuth2APIOptions{
		Config:           &sssoapi.OpenIDProviderConfig{Issuer: "https://sso.example.com"},
		ClientService:    env.clientSvc,
		OAuthService:     env.oauthSvc,
		UserSessionStore: env.sessionStore,
	})

	env.router = gin.New()
	require.NoError(t, webauth.LoadTemplates(env.router))
	env.router.GET("/oauth2/silent-authorize", api.SilentAuthorizeHandler)
	return env
}

func silentAuthorizeURL(state string) string {
	q := url.Values{
		"client_id":     {"client-1"},
		"redirect_uri":  {"https://app.example.com/callback"},
		"response_type": {"code"},
		"scope":         {"openid profile email"},
		"state":         {state},
		"nonce":         {"nonce-1"},
	}
	return "/oauth2/silent-authorize?" + q.Encode()
}

func (e *silentAuthorizeTestEnv) expectValidClient(requireConsent bool) {
	e.clientSvc.EXPECT().GetClient(gomock.Any(), "client-1").Return(&domain.Client{
		ID:             "client-1",
		RequireConsent: requireConsent,
	}, nil).AnyTimes()
	e.clientSvc.EXPECT().ValidateRedirectURI(gomock.Any(), "client-1", "https://app.example.com/callback").Return(nil).AnyTimes()
	e.clientSvc.EXPECT().ValidateScope(gomock.Any(), "client-1", gomock.Any()).Return(nil).AnyTimes()
	e.clientSvc.EXPECT().RequiresPKCE(gomock.Any(), "client-1").Return(false, nil).AnyTimes()
}

func TestSilentAuthorize_WithSession_PostsCode(t *testing.T) {
	env := setupSilentAuthorizeTest(t)
	env.expectValidClient(false)

	authTime := time.Now().Add(-5 * time.Minute)
	env.sessionStore.EXPECT().GetUserSession(gomock.Any(), "session-1").Return(&domain.UserSession{
		SessionID:       "session-1",
		UserID:          "user-1",
		AuthenticatedAt: authTime,
	}, nil)
	env.oauthSvc.EXPECT().GenerateAuthCode(
		gomock.Any(),
		"client-1",
		"user-1",
		"https://app.example.com/callback",
		"openid profile email",
		"",
		"",
		"nonce-1",
		authTime,
	).Return("code-123", nil)

	req := httptest.NewRequest(http.MethodGet, silentAuthorizeURL("state-1"), nil)
	req.AddCookie(&http.Cookie{Name: sssogin.SessionCookieName, Value: "session-1"})
	w := httptest.NewRecorder()
	env.router.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	body := w.Body.String()
	assert.Contains(t, body, `"type":"sso-silent-result"`)
	assert.Contains(t, body, `"state":"state-1"`)
	assert.Contains(t, body, `"code":"code-123"`)
	assert.Contains(t, body, `"https://app.example.com"`)
	assert.Contains(t, w.Header().Get("Content-Security-Policy"), "frame-ancestors https://app.example.com")
	assert.Contains(t, w.Header().Get("Content-Security-Policy"), "script-src 'nonce-")
	assert.Empty(t, w.Header().Get("X-Frame-Options"))
	assert.Equal(t, "no-store", w.Header().Get("Cache-Control"))
}

func TestSilentAuthorize_WithoutSession_PostsLoginRequired(t *testing.T) {
	env := setupSilentAuthorizeTest(t)
	env.expectValidClient(false)

	req := httptest.NewRequest(http.MethodGet, silentAuthorizeURL("state-none"), nil)
	w := httptest.NewRecorder()
	env.router.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	body := w.Body.String()
	assert.Contains(t, body, `"error":"login_required"`)
	assert.Contains(t, body, `"state":"state-none"`)
	assert.NotContains(t, body, `"code"`)
}

func TestSilentAuthorize_ConsentRequired(t *testing.T) {
	env := setupSilentAuthorizeTest(t)
	env.expectValidClient(true)

	env.sessionStore.EXPECT().GetUserSession(gomock.Any(), "session-1").Return(&domain.UserSession{
		SessionID:       "session-1",
		UserID:          "user-1",
		AuthenticatedAt: time.Now(),
	}, nil)

	req := httptest.NewRequest(http.MethodGet, silentAuthorizeURL("state-consent"), nil)
	req.AddCookie(&http.Cookie{Name: sssogin.SessionCookieName, Value: "session-1"})
	w := httptest.NewRecorder()
	env.router.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	body := w.Body.String()
	assert.Contains(t, body, `"error":"consent_required"`)
	assert.Contains(t, body, `"state":"state-consent"`)
	assert.NotContains(t, body, `"code"`)
}

func TestSilentAuthorize_RejectsNonHTTPRedirect(t *testing.T) {
	env := setupSilentAuthorizeTest(t)

	q := url.Values{
		"client_id":     {"client-1"},
		"redirect_uri":  {"myapp://callback"},
		"response_type": {"code"},
		"state":         {"state-bad"},
	}
	req := httptest.NewRequest(http.MethodGet, "/oauth2/silent-authorize?"+q.Encode(), nil)
	w := httptest.NewRecorder()
	env.router.ServeHTTP(w, req)

	require.Equal(t, http.StatusBadRequest, w.Code)
}
