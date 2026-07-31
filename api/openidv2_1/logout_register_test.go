package openidv2_1_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	sssoapi "github.com/pilab-dev/shadow-sso/api"
	sssogin "github.com/pilab-dev/shadow-sso/api/openidv2_1"
	"github.com/pilab-dev/shadow-sso/client"
	"github.com/pilab-dev/shadow-sso/domain"
	mock_domain "github.com/pilab-dev/shadow-sso/domain/mocks"
	"github.com/pilab-dev/shadow-sso/internal/metrics"
	"github.com/pilab-dev/shadow-sso/internal/oidcflow"
	"github.com/pilab-dev/shadow-sso/services"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

// newOIDCAPI constructs an OAuth2API with real in-memory stores and a mocked
// client repository, ready for route-level tests.
func newOIDCAPI(t *testing.T, ctrl *gomock.Controller, cfg *sssoapi.OpenIDProviderConfig) (*sssogin.OAuth2API, *mock_domain.MockClientRepository) {
	t.Helper()
	mockClientRepo := mock_domain.NewMockClientRepository(ctrl)
	clientService := client.NewClientService(mockClientRepo)

	api := sssogin.NewOAuth2API(&sssogin.OAuth2APIOptions{
		OAuthService:      nil,
		JSKSService:       nil,
		ClientService:     clientService,
		PkceService:       nil,
		Config:            cfg,
		FlowStore:         oidcflow.NewInMemoryFlowStore(),
		UserSessionStore:  oidcflow.NewInMemoryUserSessionStore(),
		UserRepo:          nil,
		PasswordHasher:    nil,
		FederationService: nil,
		TokenService:      nil,
		RealmKeysRepo:     nil,
		ClientRepo:        mockClientRepo,
	})
	require.NotNil(t, api)
	return api, mockClientRepo
}

func newOIDCRouter(t *testing.T, api *sssogin.OAuth2API) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.TestMode)
	router := gin.New()
	api.RegisterRoutes(router)
	return router
}

// ---------------------------------------------------------------------------
// Baseline characterization tests — pin the CURRENT behavior of the endpoints
// before Todo 2 wires them. These must PASS on the unchanged codebase.
// ---------------------------------------------------------------------------

// TestBaselineLogoutNotRegistered pins that GET /oauth2/logout is not routed
// today (gin returns 404). After implementation this test is superseded by
// TestRPInitiatedLogout.
func TestBaselineLogoutNotRegistered(t *testing.T) {
	gin.SetMode(gin.TestMode)
	metrics.InitCustomMetrics(nil)
	log.Logger = zerolog.Nop()

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	cfg := &sssoapi.OpenIDProviderConfig{
		Issuer: "http://localhost:8080",
		EnabledEndpoints: sssoapi.EndpointConfig{
			EndSession: false,
		},
	}
	api, _ := newOIDCAPI(t, ctrl, cfg)
	router := newOIDCRouter(t, api)

	req := httptest.NewRequest(http.MethodGet, "/oauth2/logout?id_token_hint=abc", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusNotFound, w.Code, "baseline: /oauth2/logout must not be routed yet")
}

// TestBaselineRegisterNotRegistered pins that POST /oauth2/register is not
// routed today (gin returns 404).
func TestBaselineRegisterNotRegistered(t *testing.T) {
	gin.SetMode(gin.TestMode)
	metrics.InitCustomMetrics(nil)
	log.Logger = zerolog.Nop()

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	cfg := &sssoapi.OpenIDProviderConfig{
		Issuer: "http://localhost:8080",
		EnabledEndpoints: sssoapi.EndpointConfig{
			Registration: false,
		},
	}
	api, _ := newOIDCAPI(t, ctrl, cfg)
	router := newOIDCRouter(t, api)

	req := httptest.NewRequest(http.MethodPost, "/oauth2/register", nil)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusNotFound, w.Code, "baseline: /oauth2/register must not be routed yet")
}

// TestBaselineDiscoveryOmitsLogoutRegistration pins that the discovery document
// does NOT advertise end_session_endpoint / registration_endpoint while the
// config defaults leave EnabledEndpoints.EndSession and .Registration false.
func TestBaselineDiscoveryOmitsLogoutRegistration(t *testing.T) {
	gin.SetMode(gin.TestMode)
	metrics.InitCustomMetrics(nil)
	log.Logger = zerolog.Nop()

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	// Mimics the current default EndpointConfig in apps/ssso/config ToOpenIDProviderConfig:
	// EndSession and Registration are NOT set (false).
	cfg := &sssoapi.OpenIDProviderConfig{
		Issuer: "http://localhost:8080",
		EnabledEndpoints: sssoapi.EndpointConfig{
			Authorization:       true,
			Token:               true,
			UserInfo:            true,
			JWKS:                true,
			Revocation:          true,
			Introspection:       true,
			DeviceAuthorization: true,
		},
	}
	api, _ := newOIDCAPI(t, ctrl, cfg)
	router := newOIDCRouter(t, api)

	req := httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	var doc map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &doc))
	_, hasEndSession := doc["end_session_endpoint"]
	_, hasRegistration := doc["registration_endpoint"]
	require.False(t, hasEndSession, "baseline: end_session_endpoint must not be advertised yet")
	require.False(t, hasRegistration, "baseline: registration_endpoint must not be advertised yet")
}

// ---------------------------------------------------------------------------
// Failing-first tests for the new behavior (Todo 2).
// ---------------------------------------------------------------------------

// fakeLogoutNotifier is an injectable BackchannelLogoutNotifier that records
// dispatch calls without doing network I/O.
type fakeLogoutNotifier struct {
	mu      sync.Mutex
	calls   []notifyCall
	notifyC chan struct{}
}

type notifyCall struct {
	clientID    string
	logoutToken string
}

func newFakeLogoutNotifier() *fakeLogoutNotifier {
	return &fakeLogoutNotifier{notifyC: make(chan struct{}, 8)}
}

func (f *fakeLogoutNotifier) NotifyLogout(_ context.Context, client *domain.Client, logoutToken string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, notifyCall{clientID: client.ID, logoutToken: logoutToken})
	f.notifyC <- struct{}{}
	return nil
}

func (f *fakeLogoutNotifier) waitForDispatch(t *testing.T, expected int) {
	t.Helper()
	deadline := time.After(2 * time.Second)
	for i := 0; i < expected; i++ {
		select {
		case <-f.notifyC:
		case <-deadline:
			t.Fatalf("backchannel logout dispatch #%d not observed within timeout", i+1)
		}
	}
}

func (f *fakeLogoutNotifier) total() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

func (f *fakeLogoutNotifier) call(i int) notifyCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls[i]
}

// newFullOIDCAPI builds an OAuth2API wired with everything the logout/register
// endpoints need: a real HS256 signer, a mocked session repository, a mocked
// client repository behind client.ClientService, and a fake backchannel
// notifier. It returns the in-memory user session store so tests can seed OP
// sessions for the cookie-clear path.
func newFullOIDCAPI(t *testing.T, ctrl *gomock.Controller, cfg *sssoapi.OpenIDProviderConfig) (*sssogin.OAuth2API, *mock_domain.MockClientRepository, *mock_domain.MockSessionRepository, *fakeLogoutNotifier, *oidcflow.InMemoryUserSessionStore) {
	t.Helper()
	mockClientRepo := mock_domain.NewMockClientRepository(ctrl)
	mockSessionRepo := mock_domain.NewMockSessionRepository(ctrl)
	clientService := client.NewClientService(mockClientRepo)
	userSessionStore := oidcflow.NewInMemoryUserSessionStore()

	signer := services.NewTokenSigner()
	signer.AddKeySigner("test-secret-for-hs256-logout-test")
	notifier := newFakeLogoutNotifier()

	api := sssogin.NewOAuth2API(&sssogin.OAuth2APIOptions{
		OAuthService:      nil,
		JSKSService:       nil,
		ClientService:     clientService,
		PkceService:       nil,
		Config:            cfg,
		FlowStore:         oidcflow.NewInMemoryFlowStore(),
		UserSessionStore:  userSessionStore,
		UserRepo:          nil,
		PasswordHasher:    nil,
		FederationService: nil,
		TokenService:      nil,
		RealmKeysRepo:     nil,
		ClientRepo:        mockClientRepo,
		TokenSigner:       signer,
		SessionRepo:       mockSessionRepo,
		BootstrapToken:    "initial-access-token-123",
		BackchannelLogoutNotifier: notifier,
	})
	require.NotNil(t, api)
	return api, mockClientRepo, mockSessionRepo, notifier, userSessionStore
}

// signTestIDTokenHint signs an ID-token-hint-style JWT with the test signer.
func signTestIDTokenHint(t *testing.T, claims map[string]interface{}) string {
	t.Helper()
	signer := services.NewTokenSigner()
	signer.AddKeySigner("test-secret-for-hs256-logout-test")
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims(claims))
	signed, err := token.SignedString([]byte("test-secret-for-hs256-logout-test"))
	require.NoError(t, err)
	return signed
}

func defaultTestConfig() *sssoapi.OpenIDProviderConfig {
	return &sssoapi.OpenIDProviderConfig{
		Issuer: "http://localhost:8080",
		EnabledEndpoints: sssoapi.EndpointConfig{
			EndSession:   true,
			Registration: true,
		},
	}
}

// TestRPInitiatedLogout_AllowedRedirect asserts acceptance criterion (a):
// valid id_token_hint + allowed post_logout_redirect_uri → 302 echoing state,
// and the domain.Session is revoked in the repository.
func TestRPInitiatedLogout_AllowedRedirect(t *testing.T) {
	gin.SetMode(gin.TestMode)
	metrics.InitCustomMetrics(nil)
	log.Logger = zerolog.Nop()

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	api, mockClientRepo, mockSessionRepo, _, userSessionStore := newFullOIDCAPI(t, ctrl, defaultTestConfig())
	router := newOIDCRouter(t, api)

	const (
		clientID      = "rp-client"
		redirectURI   = "https://rp.example.com/callback"
		sessionID     = "session-abc"
		tokenID       = "jti-xyz"
		userID        = "user-1"
		ssoCookieVal  = "op-cookie-1"
		stateValue    = "state-abc123"
	)

	mockClientRepo.EXPECT().GetClient(gomock.Any(), clientID).Return(&domain.Client{
		ID:             clientID,
		PostLogoutURIs: []string{redirectURI},
		BackchannelLogoutURI: "",
	}, nil).AnyTimes()

	mockSessionRepo.EXPECT().GetSessionByTokenID(gomock.Any(), sessionID).Return(&domain.Session{
		ID:        sessionID,
		UserID:    userID,
		TokenID:   tokenID,
		IsRevoked: false,
	}, nil).Times(1)
	mockSessionRepo.EXPECT().UpdateSession(gomock.Any(), gomock.Any()).DoAndReturn(
		func(_ context.Context, s *domain.Session) error {
			require.True(t, s.IsRevoked, "session must be marked revoked")
			return nil
		}).Times(1)

	// Seed an OP user session so the cookie-clear path is exercised.
	require.NoError(t, userSessionStore.StoreUserSession(context.Background(), &domain.UserSession{
		SessionID: ssoCookieVal,
		UserID:    userID,
		ExpiresAt: time.Now().Add(time.Hour),
	}))

	idTokenHint := signTestIDTokenHint(t, map[string]interface{}{
		"iss": "http://localhost:8080",
		"aud": clientID,
		"sub": userID,
		"jti": tokenID,
		"sid": sessionID,
		"exp": time.Now().Add(time.Hour).Unix(),
	})

	req := httptest.NewRequest(http.MethodGet, "/oauth2/logout", nil)
	q := req.URL.Query()
	q.Set("id_token_hint", idTokenHint)
	q.Set("post_logout_redirect_uri", redirectURI)
	q.Set("state", stateValue)
	req.URL.RawQuery = q.Encode()
	req.AddCookie(&http.Cookie{Name: sssogin.SessionCookieName, Value: ssoCookieVal})

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusFound, w.Code)
	require.Equal(t, redirectURI+"?state="+stateValue, w.Header().Get("Location"))

	// sso_op_session cookie must be cleared.
	var clearedCookie *http.Cookie
	for _, c := range w.Result().Cookies() {
		if c.Name == sssogin.SessionCookieName {
			clearedCookie = c
		}
	}
	require.NotNil(t, clearedCookie, "sso_op_session cookie must be cleared")
	require.Empty(t, clearedCookie.Value)
}

// TestRPInitiatedLogout_SidPreference asserts sid is preferred over jti when
// both are present in the id_token_hint.
func TestRPInitiatedLogout_SidPreference(t *testing.T) {
	gin.SetMode(gin.TestMode)
	metrics.InitCustomMetrics(nil)
	log.Logger = zerolog.Nop()

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	api, mockClientRepo, mockSessionRepo, _, _ := newFullOIDCAPI(t, ctrl, defaultTestConfig())
	router := newOIDCRouter(t, api)

	const (
		clientID    = "rp-client"
		redirectURI = "https://rp.example.com/callback"
		tokenID     = "jti-other"
	)

	mockClientRepo.EXPECT().GetClient(gomock.Any(), clientID).Return(&domain.Client{
		ID:             clientID,
		PostLogoutURIs: []string{redirectURI},
	}, nil).AnyTimes()

	// Only GetSessionByTokenID(sid) is consulted; the jti lookup must NOT happen.
	mockSessionRepo.EXPECT().GetSessionByTokenID(gomock.Any(), "sid-primary").Return(&domain.Session{
		ID: "sid-primary", UserID: "user-1", TokenID: tokenID,
	}, nil).Times(1)
	mockSessionRepo.EXPECT().UpdateSession(gomock.Any(), gomock.Any()).Return(nil).Times(1)

	idTokenHint := signTestIDTokenHint(t, map[string]interface{}{
		"iss": "http://localhost:8080",
		"aud": clientID,
		"sub": "user-1",
		"jti": tokenID,
		"sid": "sid-primary",
		"exp": time.Now().Add(time.Hour).Unix(),
	})

	req := httptest.NewRequest(http.MethodGet, "/oauth2/logout?id_token_hint="+idTokenHint+"&post_logout_redirect_uri="+redirectURI, nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusFound, w.Code)
}

// TestRPInitiatedLogout_DisallowedRedirect asserts acceptance criterion (b):
// a post_logout_redirect_uri that is NOT in the client's allow-list yields an
// error response and the session is NOT revoked.
func TestRPInitiatedLogout_DisallowedRedirect(t *testing.T) {
	gin.SetMode(gin.TestMode)
	metrics.InitCustomMetrics(nil)
	log.Logger = zerolog.Nop()

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	api, mockClientRepo, mockSessionRepo, _, _ := newFullOIDCAPI(t, ctrl, defaultTestConfig())
	router := newOIDCRouter(t, api)

	const (
		clientID    = "rp-client"
		redirectURI = "https://rp.example.com/callback"
		evilURI     = "https://evil.example.com/phish"
		tokenID     = "jti-xyz"
	)

	mockClientRepo.EXPECT().GetClient(gomock.Any(), clientID).Return(&domain.Client{
		ID:             clientID,
		PostLogoutURIs: []string{redirectURI},
	}, nil).AnyTimes()

	// No session lookup and no update may occur: the request must be rejected
	// before touching the session.
	mockSessionRepo.EXPECT().GetSessionByTokenID(gomock.Any(), gomock.Any()).Times(0)
	mockSessionRepo.EXPECT().UpdateSession(gomock.Any(), gomock.Any()).Times(0)

	idTokenHint := signTestIDTokenHint(t, map[string]interface{}{
		"iss": "http://localhost:8080",
		"aud": clientID,
		"sub": "user-1",
		"jti": tokenID,
		"exp": time.Now().Add(time.Hour).Unix(),
	})

	req := httptest.NewRequest(http.MethodGet, "/oauth2/logout", nil)
	q := req.URL.Query()
	q.Set("id_token_hint", idTokenHint)
	q.Set("post_logout_redirect_uri", evilURI)
	req.URL.RawQuery = q.Encode()

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusBadRequest, w.Code, "disallowed redirect must be rejected")
	require.Empty(t, w.Header().Get("Location"), "must never redirect to a non-allow-listed URI")
}

// TestRPInitiatedLogout_InvalidIDTokenHint asserts acceptance criterion (c):
// malformed or expired id_token_hint → 400 and no session revocation.
func TestRPInitiatedLogout_InvalidIDTokenHint(t *testing.T) {
	gin.SetMode(gin.TestMode)
	metrics.InitCustomMetrics(nil)
	log.Logger = zerolog.Nop()

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	api, mockClientRepo, mockSessionRepo, _, _ := newFullOIDCAPI(t, ctrl, defaultTestConfig())
	router := newOIDCRouter(t, api)

	mockClientRepo.EXPECT().GetClient(gomock.Any(), gomock.Any()).Times(0)
	mockSessionRepo.EXPECT().GetSessionByTokenID(gomock.Any(), gomock.Any()).Times(0)
	mockSessionRepo.EXPECT().UpdateSession(gomock.Any(), gomock.Any()).Times(0)

	expired := signTestIDTokenHint(t, map[string]interface{}{
		"iss": "http://localhost:8080",
		"aud": "rp-client",
		"sub": "user-1",
		"jti": "jti-expired",
		"exp": time.Now().Add(-time.Hour).Unix(),
	})

	for name, hint := range map[string]string{
		"malformed": "not-a-jwt-at-all",
		"expired":   expired,
	} {
		t.Run(name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/oauth2/logout?id_token_hint="+hint, nil)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)
			require.Equal(t, http.StatusBadRequest, w.Code, "invalid id_token_hint must yield 400")
			require.Empty(t, w.Header().Get("Location"))
		})
	}
}

// TestRPInitiatedLogout_MissingIDTokenHint asserts 400 when id_token_hint is
// absent.
func TestRPInitiatedLogout_MissingIDTokenHint(t *testing.T) {
	gin.SetMode(gin.TestMode)
	metrics.InitCustomMetrics(nil)
	log.Logger = zerolog.Nop()

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	api, _, _, _, _ := newFullOIDCAPI(t, ctrl, defaultTestConfig())
	router := newOIDCRouter(t, api)

	req := httptest.NewRequest(http.MethodGet, "/oauth2/logout", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusBadRequest, w.Code)
}

// TestRPInitiatedLogout_DoubleLogout asserts the endpoint is idempotent: a
// second logout for an already-revoked session must not panic and must still
// complete the flow.
func TestRPInitiatedLogout_DoubleLogout(t *testing.T) {
	gin.SetMode(gin.TestMode)
	metrics.InitCustomMetrics(nil)
	log.Logger = zerolog.Nop()

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	api, mockClientRepo, mockSessionRepo, _, _ := newFullOIDCAPI(t, ctrl, defaultTestConfig())
	router := newOIDCRouter(t, api)

	const (
		clientID    = "rp-client"
		redirectURI = "https://rp.example.com/callback"
	)

	mockClientRepo.EXPECT().GetClient(gomock.Any(), clientID).Return(&domain.Client{
		ID: clientID, PostLogoutURIs: []string{redirectURI},
	}, nil).AnyTimes()

	// First call revokes; second call finds the session already revoked and
	// must not re-update.
	mockSessionRepo.EXPECT().GetSessionByTokenID(gomock.Any(), "jti-double").Return(&domain.Session{
		ID: "s-double", UserID: "user-1", TokenID: "jti-double", IsRevoked: true,
	}, nil).AnyTimes()
	mockSessionRepo.EXPECT().UpdateSession(gomock.Any(), gomock.Any()).Return(nil).Times(0)

	idTokenHint := signTestIDTokenHint(t, map[string]interface{}{
		"iss": "http://localhost:8080", "aud": clientID, "sub": "user-1",
		"jti": "jti-double", "exp": time.Now().Add(time.Hour).Unix(),
	})

	for i := 0; i < 2; i++ {
		req := httptest.NewRequest(http.MethodGet, "/oauth2/logout?id_token_hint="+idTokenHint+"&post_logout_redirect_uri="+redirectURI, nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		require.Equal(t, http.StatusFound, w.Code, "double logout must stay idempotent")
	}
}

// TestRPInitiatedLogout_BackchannelDispatch asserts the back-channel logout
// token is dispatched (fire-and-forget) to a client that registered a
// BackchannelLogoutURI.
func TestRPInitiatedLogout_BackchannelDispatch(t *testing.T) {
	gin.SetMode(gin.TestMode)
	metrics.InitCustomMetrics(nil)
	log.Logger = zerolog.Nop()

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	api, mockClientRepo, mockSessionRepo, notifier, _ := newFullOIDCAPI(t, ctrl, defaultTestConfig())
	router := newOIDCRouter(t, api)

	const (
		clientID    = "rp-client"
		redirectURI = "https://rp.example.com/callback"
		sessionID   = "s-bc"
		tokenID     = "jti-bc"
	)

	mockClientRepo.EXPECT().GetClient(gomock.Any(), clientID).Return(&domain.Client{
		ID:                   clientID,
		PostLogoutURIs:       []string{redirectURI},
		BackchannelLogoutURI: "https://rp.example.com/backchannel-logout",
	}, nil).AnyTimes()

	mockSessionRepo.EXPECT().GetSessionByTokenID(gomock.Any(), sessionID).Return(&domain.Session{
		ID: sessionID, UserID: "user-1", TokenID: tokenID,
	}, nil).Times(1)
	mockSessionRepo.EXPECT().UpdateSession(gomock.Any(), gomock.Any()).Return(nil).Times(1)

	idTokenHint := signTestIDTokenHint(t, map[string]interface{}{
		"iss": "http://localhost:8080", "aud": clientID, "sub": "user-1",
		"jti": tokenID, "sid": sessionID, "exp": time.Now().Add(time.Hour).Unix(),
	})

	req := httptest.NewRequest(http.MethodGet, "/oauth2/logout?id_token_hint="+idTokenHint+"&post_logout_redirect_uri="+redirectURI, nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusFound, w.Code)
	notifier.waitForDispatch(t, 1)
	require.Equal(t, clientID, notifier.call(0).clientID)
	require.NotEmpty(t, notifier.call(0).logoutToken)
}

// TestRegisterClient_WithInitialAccessToken asserts acceptance criterion (d):
// POST /oauth2/register with a valid initial access token returns client_id and
// client_secret.
func TestRegisterClient_WithInitialAccessToken(t *testing.T) {
	gin.SetMode(gin.TestMode)
	metrics.InitCustomMetrics(nil)
	log.Logger = zerolog.Nop()

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	api, mockClientRepo, _, _, _ := newFullOIDCAPI(t, ctrl, defaultTestConfig())
	router := newOIDCRouter(t, api)

	mockClientRepo.EXPECT().CreateClient(gomock.Any(), gomock.Any()).DoAndReturn(
		func(_ context.Context, c *domain.Client) error {
			require.NotEmpty(t, c.ID)
			require.NotEmpty(t, c.Name)
			require.Equal(t, domain.ClientTypeConfidential, c.Type)
			require.Equal(t, []string{"https://rp.example.com/cb"}, c.RedirectURIs)
			return nil
		}).Times(1)

	body := `{"client_name":"DCR Client","client_type":"confidential","redirect_uris":["https://rp.example.com/cb"],"token_endpoint_auth_method":"client_secret_basic"}`
	req := httptest.NewRequest(http.MethodPost, "/oauth2/register", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer initial-access-token-123")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	var resp map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	require.NotEmpty(t, resp["client_id"])
	require.NotEmpty(t, resp["client_secret"], "confidential client must receive a plaintext client_secret")
}

// TestRegisterClient_NoToken asserts acceptance criterion (e): register without
// an initial access token → 401.
func TestRegisterClient_NoToken(t *testing.T) {
	gin.SetMode(gin.TestMode)
	metrics.InitCustomMetrics(nil)
	log.Logger = zerolog.Nop()

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	api, mockClientRepo, _, _, _ := newFullOIDCAPI(t, ctrl, defaultTestConfig())
	router := newOIDCRouter(t, api)

	mockClientRepo.EXPECT().CreateClient(gomock.Any(), gomock.Any()).Times(0)

	body := `{"client_name":"DCR Client","redirect_uris":["https://rp.example.com/cb"]}`
	req := httptest.NewRequest(http.MethodPost, "/oauth2/register", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusUnauthorized, w.Code)
}

// TestRegisterClient_RejectsBadToken asserts a wrong initial access token is
// rejected with 401.
func TestRegisterClient_RejectsBadToken(t *testing.T) {
	gin.SetMode(gin.TestMode)
	metrics.InitCustomMetrics(nil)
	log.Logger = zerolog.Nop()

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	api, mockClientRepo, _, _, _ := newFullOIDCAPI(t, ctrl, defaultTestConfig())
	router := newOIDCRouter(t, api)

	mockClientRepo.EXPECT().CreateClient(gomock.Any(), gomock.Any()).Times(0)

	req := httptest.NewRequest(http.MethodPost, "/oauth2/register", strings.NewReader(`{"client_name":"x"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer wrong-token")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusUnauthorized, w.Code)
}

// TestDiscoveryAdvertisesLogoutRegistration asserts acceptance criterion (f):
// once EnabledEndpoints.EndSession/Registration are true the discovery document
// advertises end_session_endpoint and registration_endpoint.
func TestDiscoveryAdvertisesLogoutRegistration(t *testing.T) {
	gin.SetMode(gin.TestMode)
	metrics.InitCustomMetrics(nil)
	log.Logger = zerolog.Nop()

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	api, _, _, _, _ := newFullOIDCAPI(t, ctrl, defaultTestConfig())
	router := newOIDCRouter(t, api)

	req := httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil)
	req.Host = "localhost:8080"
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	var doc map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &doc))
	require.Equal(t, "http://localhost:8080/oauth2/logout", doc["end_session_endpoint"])
	require.Equal(t, "http://localhost:8080/oauth2/register", doc["registration_endpoint"])
}
