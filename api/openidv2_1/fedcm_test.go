package openidv2_1_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	sssoapi "github.com/pilab-dev/shadow-sso/api"
	sssogin "github.com/pilab-dev/shadow-sso/api/openidv2_1"
	"github.com/pilab-dev/shadow-sso/domain"
	mock_domain "github.com/pilab-dev/shadow-sso/domain/mocks"
	services_mocks "github.com/pilab-dev/shadow-sso/services/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func TestFedCM_Flow(t *testing.T) {
	gin.SetMode(gin.TestMode)
	ctrl := gomock.NewController(t)
	clientSvc := services_mocks.NewMockClientService(ctrl)
	tokenSvc := services_mocks.NewMockTokenService(ctrl)
	sessions := mock_domain.NewMockUserSessionStore(ctrl)
	users := mock_domain.NewMockUserRepository(ctrl)

	users.EXPECT().GetUserByID(gomock.Any(), "user-1").Return(&domain.User{ID: "user-1", Email: "u@example.com", FirstName: "Test", LastName: "User"}, nil).AnyTimes()
	sessions.EXPECT().GetUserSession(gomock.Any(), "s1").Return(&domain.UserSession{SessionID: "s1", UserID: "user-1", AuthenticatedAt: time.Now()}, nil).AnyTimes()
	clientSvc.EXPECT().GetClient(gomock.Any(), "client-1").Return(&domain.Client{
		ID: "client-1", RedirectURIs: []string{"https://app.example.com/cb"}, AllowedScopes: []string{"openid", "email"}, PolicyURI: "https://app.example.com/privacy",
	}, nil).AnyTimes()
	clientSvc.EXPECT().GetClient(gomock.Any(), gomock.Any()).Return(nil, domain.ErrClientNotFound).AnyTimes()
	tokenSvc.EXPECT().GenerateIDToken(gomock.Any(), "user-1", "client-1", "n-1", "", gomock.Any(), "openid email").Return("id.token.value", nil).Times(2)

	api := sssogin.NewOAuth2API(&sssogin.OAuth2APIOptions{
		Config:           &sssoapi.OpenIDProviderConfig{Issuer: "https://sso.example.com"},
		ClientService:    clientSvc,
		TokenService:     tokenSvc,
		UserSessionStore: sessions,
		UserRepo:         users,
	})
	r := gin.New()
	r.GET("/.well-known/web-identity", api.FedCMWebIdentityHandler)
	r.GET("/fedcm/config.json", api.FedCMConfigHandler)
	r.GET("/fedcm/accounts", api.FedCMAccountsHandler)
	r.GET("/fedcm/client_metadata", api.FedCMClientMetadataHandler)
	r.POST("/fedcm/assertion", api.FedCMAssertionHandler)

	do := func(req *http.Request, fedcm bool) *httptest.ResponseRecorder {
		if fedcm {
			req.Header.Set("Sec-Fetch-Dest", "webidentity")
		}
		req.AddCookie(&http.Cookie{Name: sssogin.SessionCookieName, Value: "s1"})
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		return w
	}
	assertion := func(origin, account string) *http.Request {
		form := url.Values{"client_id": {"client-1"}, "nonce": {"n-1"}, "account_id": {account}}
		req := httptest.NewRequest(http.MethodPost, "/fedcm/assertion", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Origin", origin)
		return req
	}
	// Chrome 145+ sends the nonce inside the params JSON blob.
	paramsAssertion := func(origin, account string) *http.Request {
		params, err := json.Marshal(map[string]string{"nonce": "n-1"})
		require.NoError(t, err)
		form := url.Values{"client_id": {"client-1"}, "params": {string(params)}, "account_id": {account}}
		req := httptest.NewRequest(http.MethodPost, "/fedcm/assertion", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Origin", origin)
		return req
	}

	w := do(httptest.NewRequest(http.MethodGet, "/.well-known/web-identity", nil), false)
	assert.Contains(t, w.Body.String(), "https://sso.example.com/fedcm/config.json")
	assert.Contains(t, w.Body.String(), "https://sso.example.com/fedcm/accounts")
	assert.Contains(t, w.Body.String(), "https://sso.example.com/login?fedcm=1")
	w = do(httptest.NewRequest(http.MethodGet, "/fedcm/config.json", nil), false)
	assert.Contains(t, w.Body.String(), "id_assertion_endpoint")
	assert.Contains(t, w.Body.String(), `"supports_use_other_account":true`)
	assert.Contains(t, w.Body.String(), "https://sso.example.com/login?fedcm=1")

	assert.Equal(t, http.StatusBadRequest, do(httptest.NewRequest(http.MethodGet, "/fedcm/accounts", nil), false).Code)
	w = do(httptest.NewRequest(http.MethodGet, "/fedcm/accounts", nil), true)
	require.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), `"id":"user-1"`)
	assert.Contains(t, w.Body.String(), `"name":"Test User"`)

	// Signed-out FedCM requests must return 401, as required by the FedCM spec.
	signedOut := httptest.NewRequest(http.MethodGet, "/fedcm/accounts", nil)
	signedOut.Header.Set("Sec-Fetch-Dest", "webidentity")
	w = httptest.NewRecorder()
	r.ServeHTTP(w, signedOut)
	assert.Equal(t, http.StatusUnauthorized, w.Code)

	w = do(httptest.NewRequest(http.MethodGet, "/fedcm/client_metadata?client_id=client-1", nil), true)
	assert.Contains(t, w.Body.String(), "privacy_policy_url")

	assert.Equal(t, http.StatusForbidden, do(assertion("https://evil.example.com", "user-1"), true).Code)
	assert.Equal(t, http.StatusUnauthorized, do(assertion("https://app.example.com", "someone-else"), true).Code)

	w = do(assertion("https://app.example.com", "user-1"), true)
	require.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), `"token":"id.token.value"`)
	assert.Equal(t, "https://app.example.com", w.Header().Get("Access-Control-Allow-Origin"))
	assert.Equal(t, "true", w.Header().Get("Access-Control-Allow-Credentials"))

	w = do(paramsAssertion("https://app.example.com", "user-1"), true)
	require.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), `"token":"id.token.value"`)
}
