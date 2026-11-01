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
	userRepo     *mock_domain.MockUserRepository
}

func setupSilentAuthorizeTest(t *testing.T) *silentAuthorizeTestEnv {
	t.Helper()
	gin.SetMode(gin.TestMode)
	ctrl := gomock.NewController(t)

	env := &silentAuthorizeTestEnv{
		clientSvc:    services_mocks.NewMockClientService(ctrl),
		oauthSvc:     services_mocks.NewMockOAuthService(ctrl),
		sessionStore: mock_domain.NewMockUserSessionStore(ctrl),
		userRepo:     mock_domain.NewMockUserRepository(ctrl),
	}
	env.userRepo.EXPECT().GetUserByID(gomock.Any(), "user-1").Return(&domain.User{
		ID:        "user-1",
		Email:     "user@example.com",
		FirstName: "Test",
		LastName:  "User",
	}, nil).AnyTimes()

	api := sssogin.NewOAuth2API(&sssogin.OAuth2APIOptions{
		Config:           &sssoapi.OpenIDProviderConfig{Issuer: "https://sso.example.com"},
		ClientService:    env.clientSvc,
		OAuthService:     env.oauthSvc,
		UserSessionStore: env.sessionStore,
		UserRepo:         env.userRepo,
	})

	env.router = gin.New()
	require.NoError(t, webauth.LoadTemplates(env.router))
	env.router.GET("/oauth2/silent-authorize", api.SilentAuthorizeHandler)
	env.router.HEAD("/oauth2/silent-authorize", api.SilentAuthorizeHandler)
	env.router.OPTIONS("/oauth2/silent-authorize", api.SilentAuthorizeHandler)
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

func TestSilentAuthorize_SessionMode_PostsUser(t *testing.T) {
	env := setupSilentAuthorizeTest(t)
	env.expectValidClient(false)

	env.sessionStore.EXPECT().GetUserSession(gomock.Any(), "session-1").Return(&domain.UserSession{
		SessionID:       "session-1",
		UserID:          "user-1",
		AuthenticatedAt: time.Now(),
	}, nil)

	req := httptest.NewRequest(http.MethodGet, silentAuthorizeURL("state-session")+"&mode=session", nil)
	req.AddCookie(&http.Cookie{Name: sssogin.SessionCookieName, Value: "session-1"})
	w := httptest.NewRecorder()
	env.router.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	body := w.Body.String()
	assert.Contains(t, body, `"authenticated":true`)
	assert.Contains(t, body, `"state":"state-session"`)
	assert.Contains(t, body, `"user":{"id":"user-1"`)
	assert.Contains(t, body, `"email":"user@example.com"`)
	assert.Contains(t, body, `"name":"Test User"`)
	assert.NotContains(t, body, `"code"`)
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

func TestSilentAuthorize_ParentOriginNotAllowed(t *testing.T) {
	env := setupSilentAuthorizeTest(t)
	env.expectValidClient(false)

	q := url.Values{
		"client_id":     {"client-1"},
		"redirect_uri":  {"https://app.example.com/callback"},
		"response_type": {"code"},
		"scope":         {"openid profile email"},
		"state":         {"state-origin"},
		"parent_origin": {"https://evil.example.com"},
	}
	req := httptest.NewRequest(http.MethodGet, "/oauth2/silent-authorize?"+q.Encode(), nil)
	w := httptest.NewRecorder()
	env.router.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	body := w.Body.String()
	assert.Contains(t, body, `"error":"origin_not_allowed"`)
	assert.Contains(t, body, `"state":"state-origin"`)
	assert.NotContains(t, body, `"code"`)
	assert.Contains(t, w.Header().Get("Content-Security-Policy"), "frame-ancestors https://evil.example.com")
}

func TestSilentAuthorize_AllowedParentOrigin(t *testing.T) {
	env := setupSilentAuthorizeTest(t)
	env.expectValidClient(false)

	q := url.Values{
		"client_id":     {"client-1"},
		"redirect_uri":  {"https://app.example.com/callback"},
		"response_type": {"code"},
		"scope":         {"openid profile email"},
		"state":         {"state-ok"},
		"parent_origin": {"https://app.example.com"},
	}
	req := httptest.NewRequest(http.MethodGet, "/oauth2/silent-authorize?"+q.Encode(), nil)
	w := httptest.NewRecorder()
	env.router.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), `"error":"login_required"`)
	assert.Contains(t, w.Header().Get("Content-Security-Policy"), "frame-ancestors https://app.example.com")
}

func TestSilentAuthorize_RejectsParentOriginWithPath(t *testing.T) {
	env := setupSilentAuthorizeTest(t)

	q := url.Values{
		"client_id":     {"client-1"},
		"redirect_uri":  {"https://app.example.com/callback"},
		"response_type": {"code"},
		"parent_origin": {"https://app.example.com/nested"},
	}
	req := httptest.NewRequest(http.MethodGet, "/oauth2/silent-authorize?"+q.Encode(), nil)
	w := httptest.NewRecorder()
	env.router.ServeHTTP(w, req)

	require.Equal(t, http.StatusBadRequest, w.Code)
}

func TestSilentAuthorizePreflight_HEAD(t *testing.T) {
	env := setupSilentAuthorizeTest(t)
	env.expectValidClient(false)

	q := url.Values{
		"client_id":     {"client-1"},
		"redirect_uri":  {"https://app.example.com/callback"},
		"scope":         {"openid profile email"},
		"parent_origin": {"https://app.example.com"},
	}
	req := httptest.NewRequest(http.MethodHead, "/oauth2/silent-authorize?"+q.Encode(), nil)
	req.Header.Set("Origin", "https://app.example.com")
	w := httptest.NewRecorder()
	env.router.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "https://app.example.com", w.Header().Get("Access-Control-Allow-Origin"))
	assert.Equal(t, "Origin", w.Header().Get("Vary"))
	assert.Contains(t, w.Header().Get("Access-Control-Expose-Headers"), "Content-Security-Policy")
	assert.Contains(t, w.Header().Get("Access-Control-Expose-Headers"), "X-Frame-Options")
	assert.Contains(t, w.Header().Get("Content-Security-Policy"), "frame-ancestors https://app.example.com")
	assert.Empty(t, w.Header().Get("X-Frame-Options"))
	assert.Equal(t, "no-store", w.Header().Get("Cache-Control"))
}

func TestSilentAuthorizePreflight_OPTIONS(t *testing.T) {
	env := setupSilentAuthorizeTest(t)
	env.expectValidClient(false)

	q := url.Values{
		"client_id":     {"client-1"},
		"redirect_uri":  {"https://app.example.com/callback"},
		"scope":         {"openid profile email"},
		"parent_origin": {"https://app.example.com"},
	}
	req := httptest.NewRequest(http.MethodOptions, "/oauth2/silent-authorize?"+q.Encode(), nil)
	req.Header.Set("Origin", "https://app.example.com")
	w := httptest.NewRecorder()
	env.router.ServeHTTP(w, req)

	require.Equal(t, http.StatusNoContent, w.Code)
	assert.Equal(t, "https://app.example.com", w.Header().Get("Access-Control-Allow-Origin"))
	assert.Contains(t, w.Header().Get("Access-Control-Allow-Methods"), "HEAD")
}

func TestSilentAuthorizePreflight_OriginMismatchNotExposed(t *testing.T) {
	env := setupSilentAuthorizeTest(t)
	env.expectValidClient(false)

	q := url.Values{
		"client_id":     {"client-1"},
		"redirect_uri":  {"https://app.example.com/callback"},
		"scope":         {"openid profile email"},
		"parent_origin": {"https://app.example.com"},
	}
	req := httptest.NewRequest(http.MethodHead, "/oauth2/silent-authorize?"+q.Encode(), nil)
	req.Header.Set("Origin", "https://evil.example.com")
	w := httptest.NewRecorder()
	env.router.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	assert.Empty(t, w.Header().Get("Access-Control-Allow-Origin"))
	assert.Contains(t, w.Header().Get("Content-Security-Policy"), "frame-ancestors https://app.example.com")
}

func TestSilentAuthorizePreflight_InvalidParentOrigin(t *testing.T) {
	env := setupSilentAuthorizeTest(t)

	q := url.Values{
		"client_id":     {"client-1"},
		"redirect_uri":  {"https://app.example.com/callback"},
		"parent_origin": {"https://app.example.com/nested"},
	}
	req := httptest.NewRequest(http.MethodHead, "/oauth2/silent-authorize?"+q.Encode(), nil)
	req.Header.Set("Origin", "https://app.example.com")
	w := httptest.NewRecorder()
	env.router.ServeHTTP(w, req)

	require.Equal(t, http.StatusBadRequest, w.Code)
	assert.Empty(t, w.Header().Get("Access-Control-Allow-Origin"))
}
