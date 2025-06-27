package sssogin_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	ssso "github.com/pilab-dev/shadow-sso"
	sssogin "github.com/pilab-dev/shadow-sso/api/gin"
	"github.com/pilab-dev/shadow-sso/cache"
	"github.com/pilab-dev/shadow-sso/client"
	mock_client "github.com/pilab-dev/shadow-sso/client/mocks"
	mock_domain "github.com/pilab-dev/shadow-sso/domain/mocks"
	"github.com/pilab-dev/shadow-sso/internal/oidcflow"
	"github.com/pilab-dev/shadow-sso/services"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	// Assuming mocks are generated in these locations or similar
)

func setupAuthorizeHandlerTest(t *testing.T) (
	*gin.Engine, *oidcflow.InMemoryFlowStore,
	*mock_client.MockClientStore, *sssogin.OAuth2API,
) {
	gin.SetMode(gin.TestMode)
	log.Logger = zerolog.Nop()

	ctrl := gomock.NewController(t)

	// Other services like JWKSService, UserRepo, PasswordHasher might be needed if AuthorizeHandler uses them directly
	// For this specific test, focusing on flowID cookie, so they might not be heavily involved.

	cfg := ssso.NewDefaultConfig("http://localhost:8080")
	cfg.NextJSLoginURL = "http://localhost:3000/login"

	deviceAuthRepo := mock_domain.NewMockDeviceAuthorizationRepository(ctrl)
	authCodeRepo := mock_domain.NewMockAuthorizationCodeRepository(ctrl)
	pkceRepo := mock_domain.NewMockPkceRepository(ctrl)
	userRepo := mock_domain.NewMockUserRepository(ctrl)
	sessionRepo := mock_domain.NewMockSessionRepository(ctrl)
	clientRepo := mock_client.NewMockClientStore(ctrl)

	pubkeyRepo := mock_domain.NewMockPublicKeyRepository(ctrl)
	saRepo := mock_domain.NewMockServiceAccountRepository(ctrl)
	tokenRepo := mock_domain.NewMockTokenRepository(ctrl)

	tokenCache := cache.NewMemoryTokenStore(time.Hour * 24)
	signer := services.NewTokenSigner()

	tokenService := services.NewTokenService(
		tokenRepo, tokenCache, "issuer", signer, pubkeyRepo, saRepo, userRepo)

	jwksService, err := services.NewJWKSService(time.Hour * 24 * 365)
	require.NoError(t, err)

	mockClientStore := mock_client.NewMockClientStore(ctrl)
	mockClientService := client.NewClientService(mockClientStore)

	pkceService := services.NewPKCEService(pkceRepo)

	flowStore := oidcflow.NewInMemoryFlowStore()
	userSessionStore := oidcflow.NewInMemoryUserSessionStore()

	// OAuthService initialization
	oauthService := services.NewOAuthService(
		tokenRepo, authCodeRepo, deviceAuthRepo,
		clientRepo, userRepo, sessionRepo, tokenService, "http://localhost:8080",
	) // services.OAuthService

	// Simplified NewOAuth2API call for this test's focus
	// In a real setup, all dependencies would be properly mocked or instantiated.
	api := sssogin.NewOAuth2API(
		&sssogin.OAuth2APIOptions{
			OAuthService:  oauthService,
			JSKSService:   jwksService,
			ClientService: mockClientService,
			PkceService:   pkceService,
			Config: &ssso.OpenIDProviderConfig{
				NextJSLoginURL: "http://localhost:3000/login",
			},
			FlowStore:         flowStore,
			UserSessionStore:  userSessionStore,
			UserRepo:          userRepo,
			PasswordHasher:    nil,
			FederationService: nil,
			TokenService:      tokenService,
		}, // services.TokenService (can be nil)
	)

	router := gin.Default()
	router.GET("/oauth2/authorize", api.AuthorizeHandler)

	return router, flowStore, mockClientStore, api
}

func TestAuthorizeHandler_RedirectsToNextJS_AndSetsFlowIdCookie(t *testing.T) {
	router, mockFlowStore, mockClientStore, _ := setupAuthorizeHandlerTest(t)
	_, _ = mockFlowStore, mockClientStore

	mockClientStore.EXPECT().GetClient(gomock.Any(), "test-client").
		Return(&client.Client{
			ID:            "test-client",
			Name:          "Test App",
			RedirectURIs:  []string{"http://client.app/callback"},
			AllowedScopes: []string{"openid", "profile", "email"},
		}, nil).
		AnyTimes()

	clientID := "test-client"
	redirectURI := "http://client.app/callback"
	scope := "openid profile email"
	state := "randomstate123"
	codeChallenge := "challenge"
	codeChallengeMethod := "S256"

	// // Mock client validation calls
	// mockClientService.EXPECT().GetClient(gomock.Any(), clientID).Return(&client.Client{ID: clientID, Name: "Test App"}, nil)
	// mockClientService.EXPECT().ValidateRedirectURI(gomock.Any(), clientID, redirectURI).Return(nil)
	// mockClientService.EXPECT().ValidateScope(gomock.Any(), clientID, strings.Split(scope, " ")).Return(nil)
	// mockClientService.EXPECT().RequiresPKCE(gomock.Any(), clientID).Return(true, nil)

	// // Mock flow store
	// mockFlowStore.EXPECT().StoreFlow(gomock.Any(), gomock.Any()).
	// 	DoAndReturn(func(flowID string, state oidcflow.LoginFlowState) error {
	// 		assert.NotEmpty(t, flowID)
	// 		assert.Equal(t, clientID, state.ClientID)
	// 		// ... other assertions about flowState ...
	// 		return nil
	// 	}).Times(1)

	w := httptest.NewRecorder()
	reqURL := fmt.Sprintf("/oauth2/authorize?client_id=%s&redirect_uri=%s"+
		"&response_type=code&scope=%s&state=%s&code_challenge=%s"+
		"&code_challenge_method=%s",
		clientID, url.QueryEscape(redirectURI), url.QueryEscape(scope),
		state, codeChallenge, codeChallengeMethod,
	)
	req, _ := http.NewRequest("GET", reqURL, nil)
	req.Header.Set("X-Forwarded-Proto", "http") // Simulate http request

	router.ServeHTTP(w, req)

	println(w.Body.String())

	assert.Equal(t, http.StatusFound, w.Code)

	redirectLocation := w.Header().Get("Location")
	require.NotEmpty(t, redirectLocation, "Expected a redirect location")

	parsedRedirectURL, err := url.Parse(redirectLocation)
	require.NoError(t, err, "Failed to parse redirect URL")

	assert.Equal(t, "http", parsedRedirectURL.Scheme)
	assert.Equal(t, "localhost:3000", parsedRedirectURL.Host)
	assert.Equal(t, "/login", parsedRedirectURL.Path)

	// Check that flowId is NOT in the query parameters of the redirect URL
	assert.Empty(t, parsedRedirectURL.Query().Get("flowId"), "flowId should not be in query parameters")

	// Check for the cookie
	cookies := w.Result().Cookies() // Use w.Result().Cookies()
	var flowCookie *http.Cookie
	for _, cookie := range cookies {
		if cookie.Name == "sso_oidc_flow_id" {
			flowCookie = cookie
			break
		}
	}
	require.NotNil(t, flowCookie, "sso_oidc_flow_id cookie not set")
	assert.NotEmpty(t, flowCookie.Value, "flowId cookie value should not be empty")
	assert.True(t, flowCookie.HttpOnly, "flowId cookie should be HttpOnly")
	assert.Equal(t, "/", flowCookie.Path, "flowId cookie path should be /")
	assert.InDelta(t, (10 * time.Minute).Seconds(), float64(flowCookie.MaxAge), 1, "flowId cookie MaxAge should be around 10 minutes")
	assert.Equal(t, http.SameSiteLaxMode, flowCookie.SameSite, "flowId cookie SameSite should be Lax")
	assert.False(t, flowCookie.Secure, "flowId cookie Secure flag should be false for http request")

	// Test with X-Forwarded-Proto: https
	wSecure := httptest.NewRecorder()
	reqSecure, _ := http.NewRequest("GET", reqURL, nil)
	reqSecure.Header.Set("X-Forwarded-Proto", "https") // Simulate https request

	// Reset mocks that were already called if they are strict about Times(1)
	// For this test, we need new mocks or allow multiple calls if StoreFlow is called again.
	// Better to create new mock controller for isolated tests or ensure mocks allow multiple calls if state is shared.
	// For simplicity here, assuming mocks are fine with another call sequence if not strictly Times(1).
	// If using Times(1), this second part would need its own mock setup.
	// Let's assume the setup function handles fresh mocks or they are not strict.
	// Re-mocking for clarity (in a real test suite, use t.Run for subtests with fresh mocks)
	ctrl2 := gomock.NewController(t)
	defer ctrl2.Finish()

	router.ServeHTTP(wSecure, reqSecure)
	cookiesSecure := wSecure.Result().Cookies()
	var flowCookieSecure *http.Cookie
	for _, cookie := range cookiesSecure {
		if cookie.Name == "sso_oidc_flow_id" {
			flowCookieSecure = cookie
			break
		}
	}
	require.NotNil(t, flowCookieSecure, "sso_oidc_flow_id cookie not set for HTTPS request")
	assert.True(t, flowCookieSecure.Secure, "flowId cookie Secure flag should be true for https request")
}

// TODO: Add test for AuthorizeHandler when user is already authenticated (cookie sso_op_session is present)
// - It should bypass NextJSLoginURL and directly call redirectToClient with auth code.
// - The sso_oidc_flow_id cookie should NOT be set in this path.
// - This requires mocking userSessionStore.GetUserSession to return a valid session.
