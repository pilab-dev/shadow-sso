package integration

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"testing"

	"github.com/pilab-dev/shadow-sso/domain"
	"github.com/pilab-dev/shadow-sso/mongodb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
)

// ─── constants ───────────────────────────────────────────────────────────────

const (
	loginTestAdminEmail    = "admin@login-flows-test.local"
	loginTestAdminPassword = "Test-Password-Secure-123!"
	loginTestClientID      = "admin-ui"
	loginTestClientSecret  = "integration-test-secret-for-admin-ui-cli"

	// appClientID is a secondary client used for the authorization_code flow.
	appClientID     = "test-app"
	appClientSecret = "test-app-secret-for-integration"
	appRedirectURI  = "http://localhost/callback"

	// pkceClientID is a public client (no secret) that requires PKCE, per
	// OAuth 2.1 §2.1: public clients MUST use PKCE for authorization_code.
	pkceClientID    = "test-spa"
	pkceRedirectURI = "http://localhost/spa/callback"
)

// ─── test environment ─────────────────────────────────────────────────────────

type loginTestEnv struct {
	baseURL string
}

// setupLoginTest starts the full SSO server, seeds an admin user and the
// admin-ui client with a known plaintext secret, and returns env state.
// The server and MongoDB database are cleaned up via t.Cleanup.
func setupLoginTest(t *testing.T) loginTestEnv {
	t.Helper()

	srv, provider, baseURL := StartTestServer(t)
	if srv == nil {
		t.Skip("MongoDB not available")
		return loginTestEnv{}
	}

	t.Cleanup(func() { StopTestServer(t, srv, provider) })

	bootstrapAdminUser(t, provider, loginTestAdminEmail, loginTestAdminPassword, "Test", "Admin")
	bootstrapAdminUIClientWithSecret(t, provider, loginTestClientSecret)
	bootstrapAppClient(t, provider)
	bootstrapPublicPKCEClient(t, provider)

	return loginTestEnv{baseURL: baseURL}
}

// bootstrapAdminUIClientWithSecret seeds admin-ui with a known plaintext secret.
// It skips creation when the client already exists.
func bootstrapAdminUIClientWithSecret(t testing.TB, provider interface {
	ClientRepository(ctx context.Context) domain.ClientRepository
}, plainSecret string) {
	t.Helper()
	ctx := context.Background()
	clientRepo := provider.ClientRepository(ctx)

	if _, err := clientRepo.GetClient(ctx, loginTestClientID); err == nil {
		return // already exists
	}

	hashed, err := bcrypt.GenerateFromPassword([]byte(plainSecret), bcrypt.MinCost)
	require.NoError(t, err, "bcrypt hash for test client secret")

	client := &domain.Client{
		ID:                  loginTestClientID,
		Secret:              string(hashed),
		Type:                domain.ClientTypeConfidential,
		Name:                "Admin UI",
		AllowedGrantTypes:   []string{"password", "refresh_token", "client_credentials"},
		AllowedScopes:       []string{"openid", "profile", "email"},
		IsActive:            true,
		IsConfidential:      true,
		TokenEndpointAuth:   "client_secret_post",
		ServiceAccountRoles: []string{"ROLE_ADMIN"},
	}
	require.NoError(t, clientRepo.CreateClient(ctx, client), "create admin-ui test client")
}

// bootstrapAppClient seeds a confidential app client that supports authorization_code.
func bootstrapAppClient(t testing.TB, provider interface {
	ClientRepository(ctx context.Context) domain.ClientRepository
}) {
	t.Helper()
	ctx := context.Background()
	clientRepo := provider.ClientRepository(ctx)

	if _, err := clientRepo.GetClient(ctx, appClientID); err == nil {
		return
	}

	hashed, err := bcrypt.GenerateFromPassword([]byte(appClientSecret), bcrypt.MinCost)
	require.NoError(t, err)

	client := &domain.Client{
		ID:                mongodb.NewID(), // not used for lookup; ID is the client_id
		Secret:            string(hashed),
		Type:              domain.ClientTypeConfidential,
		Name:              "Test App",
		AllowedGrantTypes: []string{"authorization_code", "refresh_token"},
		AllowedScopes:     []string{"openid", "profile", "email"},
		RedirectURIs:      []string{appRedirectURI},
		IsActive:          true,
		IsConfidential:    true,
		TokenEndpointAuth: "client_secret_post",
		RequireConsent:    false,
	}
	// Override the mongo-generated ID with the human-readable client_id
	client.ID = appClientID
	require.NoError(t, clientRepo.CreateClient(ctx, client), "create test-app client")
}

// bootstrapPublicPKCEClient seeds a public client (no client secret) that
// requires PKCE for the authorization_code flow, as mandated by OAuth 2.1
// for clients that cannot securely hold a secret (e.g. SPAs).
func bootstrapPublicPKCEClient(t testing.TB, provider interface {
	ClientRepository(ctx context.Context) domain.ClientRepository
}) {
	t.Helper()
	ctx := context.Background()
	clientRepo := provider.ClientRepository(ctx)

	if _, err := clientRepo.GetClient(ctx, pkceClientID); err == nil {
		return
	}

	client := &domain.Client{
		ID:                pkceClientID,
		Type:              domain.ClientTypePublic,
		Name:              "Test SPA",
		AllowedGrantTypes: []string{"authorization_code", "refresh_token"},
		AllowedScopes:     []string{"openid", "profile", "email"},
		RedirectURIs:      []string{pkceRedirectURI},
		IsActive:          true,
		IsConfidential:    false,
		RequirePKCE:       true,
		TokenEndpointAuth: "none",
		RequireConsent:    false,
	}
	require.NoError(t, clientRepo.CreateClient(ctx, client), "create test-spa PKCE client")
}

// ─── HTTP helpers ─────────────────────────────────────────────────────────────

// noRedirectClient returns an *http.Client that never follows redirects.
func noRedirectClient() *http.Client {
	return &http.Client{
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// jarClient returns an *http.Client with a cookie jar and no redirect following.
func jarClient(t *testing.T) *http.Client {
	t.Helper()
	jar, err := cookiejar.New(nil)
	require.NoError(t, err)
	return &http.Client{
		Jar: jar,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// postForm POSTs form values to path, returns (statusCode, parsed JSON body).
func postForm(t *testing.T, client *http.Client, rawURL string, vals url.Values) (int, map[string]any) {
	t.Helper()
	resp, err := client.PostForm(rawURL, vals)
	require.NoError(t, err, "POST %s", rawURL)
	defer resp.Body.Close()
	body := parseJSON(t, resp.Body)
	return resp.StatusCode, body
}

// getJSON GETs a URL with optional headers, returns (statusCode, parsed JSON body).
func getJSON(t *testing.T, client *http.Client, rawURL string, headers map[string]string) (int, map[string]any) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	require.NoError(t, err)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	require.NoError(t, err, "GET %s", rawURL)
	defer resp.Body.Close()
	body := parseJSON(t, resp.Body)
	return resp.StatusCode, body
}

func parseJSON(t *testing.T, r io.Reader) map[string]any {
	t.Helper()
	data, err := io.ReadAll(r)
	require.NoError(t, err)
	var out map[string]any
	if len(data) > 0 {
		require.NoError(t, json.Unmarshal(data, &out), "parse response JSON: %s", string(data))
	}
	return out
}

// tokenEndpoint returns the /oauth2/token URL for the given base.
func tokenEndpoint(base string) string { return base + "/oauth2/token" }

// passwordGrant does a password grant and returns the full token response body.
// It fails the test on any HTTP or JSON error; it does NOT assert the status code,
// so callers can inspect error responses.
func passwordGrant(t *testing.T, base, clientID, secret, email, password, scope string) (int, map[string]any) {
	t.Helper()
	return postForm(t, noRedirectClient(), tokenEndpoint(base), url.Values{
		"grant_type":    {"password"},
		"client_id":     {clientID},
		"client_secret": {secret},
		"username":      {email},
		"password":      {password},
		"scope":         {scope},
	})
}

// mustAccessToken performs a password grant and returns the access_token string,
// failing the test if the grant does not succeed.
func mustAccessToken(t *testing.T, env loginTestEnv) string {
	t.Helper()
	status, body := passwordGrant(t, env.baseURL,
		loginTestClientID, loginTestClientSecret,
		loginTestAdminEmail, loginTestAdminPassword,
		"openid profile email",
	)
	require.Equal(t, http.StatusOK, status, "expected successful password grant, got: %v", body)
	token, ok := body["access_token"].(string)
	require.True(t, ok && token != "", "access_token missing in response: %v", body)
	return token
}

// mustRefreshToken is like mustAccessToken but also returns the refresh token.
func mustTokenPair(t *testing.T, env loginTestEnv) (access, refresh string) {
	t.Helper()
	status, body := passwordGrant(t, env.baseURL,
		loginTestClientID, loginTestClientSecret,
		loginTestAdminEmail, loginTestAdminPassword,
		"openid profile email",
	)
	require.Equal(t, http.StatusOK, status, "expected successful password grant: %v", body)
	access, _ = body["access_token"].(string)
	refresh, _ = body["refresh_token"].(string)
	require.NotEmpty(t, access, "access_token missing")
	require.NotEmpty(t, refresh, "refresh_token missing")
	return
}

// getRaw GETs a URL and returns (statusCode, rawBody) without assuming JSON.
// Used for the /oauth2/authorize endpoint, which renders HTML on error.
func getRaw(t *testing.T, client *http.Client, rawURL string) (int, string) {
	t.Helper()
	resp, err := client.Get(rawURL)
	require.NoError(t, err, "GET %s", rawURL)
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return resp.StatusCode, string(body)
}

// genPKCEPair generates a random code_verifier and its S256 code_challenge,
// per RFC 7636.
func genPKCEPair(t *testing.T) (verifier, challengeS256 string) {
	t.Helper()
	raw := make([]byte, 32)
	_, err := rand.Read(raw)
	require.NoError(t, err)
	verifier = base64.RawURLEncoding.EncodeToString(raw)

	sum := sha256.Sum256([]byte(verifier))
	challengeS256 = base64.RawURLEncoding.EncodeToString(sum[:])
	return verifier, challengeS256
}

// decodeJWTClaims decodes (without verifying) the payload segment of a
// compact JWT and returns it as a map, for asserting claim contents in tests.
func decodeJWTClaims(t *testing.T, token string) map[string]any {
	t.Helper()
	parts := strings.Split(token, ".")
	require.Len(t, parts, 3, "expected a compact JWT with 3 segments")

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	require.NoError(t, err, "decode JWT payload segment")

	var claims map[string]any
	require.NoError(t, json.Unmarshal(payload, &claims), "unmarshal JWT claims")
	return claims
}

// authorizeAndLogin drives GET /oauth2/authorize followed by
// POST /api/oidc/authenticate using the shared admin test user, and returns
// the authorization code plus the raw redirect Location. extraParams are
// merged into the /oauth2/authorize query (e.g. nonce, code_challenge).
func authorizeAndLogin(
	t *testing.T, env loginTestEnv, client *http.Client,
	clientID, redirectURI, state string, extraParams url.Values,
) (code, location string) {
	t.Helper()

	q := url.Values{
		"response_type": {"code"},
		"client_id":     {clientID},
		"redirect_uri":  {redirectURI},
		"scope":         {"openid profile email"},
		"state":         {state},
	}
	maps.Copy(q, extraParams)

	authorizeURL := env.baseURL + "/oauth2/authorize?" + q.Encode()
	resp1, err := client.Get(authorizeURL)
	require.NoError(t, err)
	resp1.Body.Close()
	require.Equal(t, http.StatusFound, resp1.StatusCode, "authorize should redirect to login")

	serverURL, err := url.Parse(env.baseURL)
	require.NoError(t, err)

	var flowID, csrfToken string
	for _, c := range client.Jar.Cookies(serverURL) {
		switch c.Name {
		case "sso_oidc_flow_id":
			flowID = c.Value
		case "sso_csrf_token":
			csrfToken = c.Value
		}
	}
	require.NotEmpty(t, flowID, "sso_oidc_flow_id cookie not set by authorize handler")
	require.NotEmpty(t, csrfToken, "sso_csrf_token cookie not set by authorize handler")

	payload, _ := json.Marshal(map[string]string{
		"flow_id":  flowID,
		"email":    loginTestAdminEmail,
		"password": loginTestAdminPassword,
	})
	authReq, err := http.NewRequest(http.MethodPost,
		env.baseURL+"/api/oidc/authenticate", bytes.NewReader(payload))
	require.NoError(t, err)
	authReq.Header.Set("Content-Type", "application/json")
	authReq.Header.Set("X-CSRF-Token", csrfToken)

	resp2, err := client.Do(authReq)
	require.NoError(t, err)
	resp2.Body.Close()
	require.Equal(t, http.StatusFound, resp2.StatusCode, "authenticate should redirect with auth code")

	location = resp2.Header.Get("Location")
	require.NotEmpty(t, location, "Location header missing after authenticate")

	loc, err := url.Parse(location)
	require.NoError(t, err)
	code = loc.Query().Get("code")
	require.NotEmpty(t, code, "authorization code missing from redirect: %s", location)

	return code, location
}

// ─── 1. OIDC Discovery ────────────────────────────────────────────────────────

func TestOIDCDiscovery(t *testing.T) {
	env := setupLoginTest(t)

	status, body := getJSON(t, noRedirectClient(), env.baseURL+"/.well-known/openid-configuration", nil)

	assert.Equal(t, http.StatusOK, status)
	assert.NotEmpty(t, body["issuer"], "issuer missing from discovery doc")
	assert.NotEmpty(t, body["authorization_endpoint"])
	assert.NotEmpty(t, body["token_endpoint"])
	assert.NotEmpty(t, body["jwks_uri"])
	assert.NotEmpty(t, body["userinfo_endpoint"])
}

// ─── 2. JWKS ─────────────────────────────────────────────────────────────────

func TestJWKS(t *testing.T) {
	env := setupLoginTest(t)

	status, body := getJSON(t, noRedirectClient(), env.baseURL+"/.well-known/jwks.json", nil)

	assert.Equal(t, http.StatusOK, status)
	keys, ok := body["keys"].([]any)
	require.True(t, ok, "keys field missing or wrong type")
	assert.NotEmpty(t, keys, "expected at least one JWK")
}

// ─── 3. Password Grant — success ─────────────────────────────────────────────

func TestPasswordGrant_Success(t *testing.T) {
	env := setupLoginTest(t)

	status, body := passwordGrant(t, env.baseURL,
		loginTestClientID, loginTestClientSecret,
		loginTestAdminEmail, loginTestAdminPassword,
		"openid profile email",
	)

	require.Equal(t, http.StatusOK, status)
	assert.NotEmpty(t, body["access_token"], "access_token")
	assert.Equal(t, "Bearer", body["token_type"])
	expiresIn, ok := body["expires_in"].(float64)
	require.True(t, ok, "expires_in must be a number")
	assert.Greater(t, expiresIn, float64(0))
}

// ─── 4. Password Grant — wrong password ──────────────────────────────────────

func TestPasswordGrant_WrongPassword(t *testing.T) {
	env := setupLoginTest(t)

	status, body := passwordGrant(t, env.baseURL,
		loginTestClientID, loginTestClientSecret,
		loginTestAdminEmail, "WRONG-PASSWORD",
		"openid",
	)

	assert.GreaterOrEqual(t, status, 400)
	assert.NotEmpty(t, body["error"], "expected error field in response")
}

// ─── 5. Password Grant — unknown user ────────────────────────────────────────

func TestPasswordGrant_UnknownUser(t *testing.T) {
	env := setupLoginTest(t)

	status, body := passwordGrant(t, env.baseURL,
		loginTestClientID, loginTestClientSecret,
		"nobody@does-not-exist.local", loginTestAdminPassword,
		"openid",
	)

	assert.GreaterOrEqual(t, status, 400)
	assert.NotEmpty(t, body["error"])
}

// ─── 6. Password Grant — grant type not allowed ───────────────────────────────

func TestPasswordGrant_GrantTypeDisallowed(t *testing.T) {
	// The test-app client only allows authorization_code; password is not in its list.
	env := setupLoginTest(t)

	status, body := passwordGrant(t, env.baseURL,
		appClientID, appClientSecret,
		loginTestAdminEmail, loginTestAdminPassword,
		"openid",
	)

	assert.GreaterOrEqual(t, status, 400)
	assert.NotEmpty(t, body["error"])
}

// ─── 7. Client Credentials — success ─────────────────────────────────────────

func TestClientCredentials_Success(t *testing.T) {
	env := setupLoginTest(t)

	status, body := postForm(t, noRedirectClient(), tokenEndpoint(env.baseURL), url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {loginTestClientID},
		"client_secret": {loginTestClientSecret},
		"scope":         {"openid"},
	})

	require.Equal(t, http.StatusOK, status)
	assert.NotEmpty(t, body["access_token"])
	assert.Equal(t, "Bearer", body["token_type"])
}

// ─── 8. Client Credentials — wrong secret ─────────────────────────────────────

func TestClientCredentials_WrongSecret(t *testing.T) {
	env := setupLoginTest(t)

	status, body := postForm(t, noRedirectClient(), tokenEndpoint(env.baseURL), url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {loginTestClientID},
		"client_secret": {"TOTALLY-WRONG-SECRET"},
		"scope":         {"openid"},
	})

	assert.GreaterOrEqual(t, status, 400)
	assert.NotEmpty(t, body["error"])
}

// ─── 9. Refresh Token — success ──────────────────────────────────────────────

func TestRefreshToken_Success(t *testing.T) {
	env := setupLoginTest(t)
	_, refreshToken := mustTokenPair(t, env)

	status, body := postForm(t, noRedirectClient(), tokenEndpoint(env.baseURL), url.Values{
		"grant_type":    {"refresh_token"},
		"client_id":     {loginTestClientID},
		"client_secret": {loginTestClientSecret},
		"refresh_token": {refreshToken},
	})

	require.Equal(t, http.StatusOK, status, "refresh token exchange failed: %v", body)
	assert.NotEmpty(t, body["access_token"], "new access_token")
	// rotation: new refresh token must be issued
	assert.NotEmpty(t, body["refresh_token"], "rotated refresh_token")
}

// ─── 10. Refresh Token — invalid token ───────────────────────────────────────

func TestRefreshToken_Invalid(t *testing.T) {
	env := setupLoginTest(t)

	status, body := postForm(t, noRedirectClient(), tokenEndpoint(env.baseURL), url.Values{
		"grant_type":    {"refresh_token"},
		"client_id":     {loginTestClientID},
		"client_secret": {loginTestClientSecret},
		"refresh_token": {"this-is-not-a-valid-refresh-token"},
	})

	assert.GreaterOrEqual(t, status, 400)
	assert.NotEmpty(t, body["error"])
}

// ─── 11. Refresh Token — reuse after rotation ────────────────────────────────

func TestRefreshToken_ReuseAfterRotation(t *testing.T) {
	env := setupLoginTest(t)
	_, oldRefresh := mustTokenPair(t, env)

	// First refresh — consumes oldRefresh
	status, body := postForm(t, noRedirectClient(), tokenEndpoint(env.baseURL), url.Values{
		"grant_type":    {"refresh_token"},
		"client_id":     {loginTestClientID},
		"client_secret": {loginTestClientSecret},
		"refresh_token": {oldRefresh},
	})
	require.Equal(t, http.StatusOK, status, "first refresh failed: %v", body)

	// Second refresh with the old (now consumed) token must fail
	status2, body2 := postForm(t, noRedirectClient(), tokenEndpoint(env.baseURL), url.Values{
		"grant_type":    {"refresh_token"},
		"client_id":     {loginTestClientID},
		"client_secret": {loginTestClientSecret},
		"refresh_token": {oldRefresh},
	})
	assert.GreaterOrEqual(t, status2, 400, "reuse of consumed refresh token should fail")
	assert.NotEmpty(t, body2["error"])
}

// ─── 12. Token Introspection — active ────────────────────────────────────────

func TestIntrospect_ActiveToken(t *testing.T) {
	env := setupLoginTest(t)
	accessToken := mustAccessToken(t, env)

	status, body := postForm(t, noRedirectClient(), env.baseURL+"/oauth2/introspect", url.Values{
		"token":         {accessToken},
		"client_id":     {loginTestClientID},
		"client_secret": {loginTestClientSecret},
	})

	require.Equal(t, http.StatusOK, status)
	active, _ := body["active"].(bool)
	assert.True(t, active, "expected active=true for a fresh access token")
	assert.NotEmpty(t, body["sub"], "sub claim missing")
	assert.Equal(t, loginTestClientID, body["client_id"])
}

// ─── 13. Token Introspection — unknown token ─────────────────────────────────

func TestIntrospect_UnknownToken(t *testing.T) {
	env := setupLoginTest(t)

	status, body := postForm(t, noRedirectClient(), env.baseURL+"/oauth2/introspect", url.Values{
		"token":         {"this.is.not.a.real.token"},
		"client_id":     {loginTestClientID},
		"client_secret": {loginTestClientSecret},
	})

	require.Equal(t, http.StatusOK, status)
	active, _ := body["active"].(bool)
	assert.False(t, active, "expected active=false for unknown token")
}

// ─── 14. Token Revocation → then introspect shows inactive ───────────────────

func TestRevokeToken_ThenIntrospect(t *testing.T) {
	env := setupLoginTest(t)
	accessToken := mustAccessToken(t, env)

	// Revoke
	revokeStatus, _ := postForm(t, noRedirectClient(), env.baseURL+"/oauth2/revoke", url.Values{
		"token":         {accessToken},
		"client_id":     {loginTestClientID},
		"client_secret": {loginTestClientSecret},
	})
	assert.Equal(t, http.StatusOK, revokeStatus, "revoke should return 200")

	// Introspect the revoked token
	status, body := postForm(t, noRedirectClient(), env.baseURL+"/oauth2/introspect", url.Values{
		"token":         {accessToken},
		"client_id":     {loginTestClientID},
		"client_secret": {loginTestClientSecret},
	})
	require.Equal(t, http.StatusOK, status)
	active, _ := body["active"].(bool)
	assert.False(t, active, "revoked token must be inactive")
}

// ─── 15. UserInfo — valid Bearer token ───────────────────────────────────────

func TestUserInfo_ValidToken(t *testing.T) {
	env := setupLoginTest(t)
	accessToken := mustAccessToken(t, env)

	status, body := getJSON(t, noRedirectClient(),
		env.baseURL+"/oauth2/userinfo",
		map[string]string{"Authorization": "Bearer " + accessToken},
	)

	require.Equal(t, http.StatusOK, status, "userinfo should succeed with valid token: %v", body)
	assert.NotEmpty(t, body["sub"], "sub claim missing from userinfo")
}

// ─── 16. UserInfo — no token → 401 ───────────────────────────────────────────

func TestUserInfo_NoToken(t *testing.T) {
	env := setupLoginTest(t)

	status, _ := getJSON(t, noRedirectClient(), env.baseURL+"/oauth2/userinfo", nil)

	assert.Equal(t, http.StatusUnauthorized, status)
}

// ─── 17. API OIDC Authenticate (Next.js path) ────────────────────────────────

// TestAPIAuthenticate_Success drives the full programmatic login path:
//
//  1. GET /oauth2/authorize  → stores flow state, sets flow_id + CSRF cookies, redirects to /login
//  2. POST /api/oidc/authenticate with correct credentials + CSRF tokens
//     → server updates flow state and redirects to redirect_uri?code=...
func TestAPIAuthenticate_Success(t *testing.T) {
	env := setupLoginTest(t)
	client := jarClient(t)

	// ── Step 1: start the authorize flow ────────────────────────────────────
	authorizeURL := fmt.Sprintf(
		"%s/oauth2/authorize?response_type=code&client_id=%s&redirect_uri=%s&scope=openid&state=test-state",
		env.baseURL, appClientID, url.QueryEscape(appRedirectURI),
	)
	resp1, err := client.Get(authorizeURL)
	require.NoError(t, err)
	resp1.Body.Close()

	// Server should redirect to /login (302) — we don't follow it
	require.Equal(t, http.StatusFound, resp1.StatusCode, "authorize should redirect to login")

	// ── Step 2: extract cookies set by the authorize handler ─────────────────
	serverURL, err := url.Parse(env.baseURL)
	require.NoError(t, err)

	var flowID, csrfToken string
	for _, c := range client.Jar.Cookies(serverURL) {
		switch c.Name {
		case "sso_oidc_flow_id":
			flowID = c.Value
		case "sso_csrf_token":
			csrfToken = c.Value
		}
	}
	require.NotEmpty(t, flowID, "sso_oidc_flow_id cookie not set by authorize handler")
	require.NotEmpty(t, csrfToken, "sso_csrf_token cookie not set by authorize handler")

	// ── Step 3: POST /api/oidc/authenticate ──────────────────────────────────
	payload, _ := json.Marshal(map[string]string{
		"flow_id":  flowID,
		"email":    loginTestAdminEmail,
		"password": loginTestAdminPassword,
	})

	authReq, err := http.NewRequest(http.MethodPost,
		env.baseURL+"/api/oidc/authenticate",
		bytes.NewReader(payload),
	)
	require.NoError(t, err)
	authReq.Header.Set("Content-Type", "application/json")
	authReq.Header.Set("X-CSRF-Token", csrfToken)

	resp2, err := client.Do(authReq)
	require.NoError(t, err)
	resp2.Body.Close()

	// Handler redirects to redirect_uri?code=...&state=...
	require.Equal(t, http.StatusFound, resp2.StatusCode, "authenticate should redirect with auth code")

	location := resp2.Header.Get("Location")
	require.NotEmpty(t, location, "Location header missing after authenticate")
	assert.True(t, strings.Contains(location, "code="),
		"redirect URL should contain authorization code, got: %s", location)
	assert.True(t, strings.Contains(location, "state=test-state"),
		"state parameter should be preserved, got: %s", location)
}

// ─── Additional: token endpoint rejects missing client_id ────────────────────

func TestTokenEndpoint_MissingClientID(t *testing.T) {
	env := setupLoginTest(t)

	status, body := postForm(t, noRedirectClient(), tokenEndpoint(env.baseURL), url.Values{
		"grant_type": {"password"},
		"username":   {loginTestAdminEmail},
		"password":   {loginTestAdminPassword},
	})

	assert.GreaterOrEqual(t, status, 400)
	assert.NotEmpty(t, body["error"])
}

// ─── Additional: unsupported grant type ──────────────────────────────────────

func TestTokenEndpoint_UnsupportedGrantType(t *testing.T) {
	env := setupLoginTest(t)

	status, body := postForm(t, noRedirectClient(), tokenEndpoint(env.baseURL), url.Values{
		"grant_type":    {"magic_wand"},
		"client_id":     {loginTestClientID},
		"client_secret": {loginTestClientSecret},
	})

	assert.GreaterOrEqual(t, status, 400)
	assert.NotEmpty(t, body["error"])
}

// ─── 18. Authorization Code — full exchange returns a spec-compliant id_token ─
//
// OIDC Core 1.0 §2 requires the id_token to carry iss, sub, aud, exp, iat and,
// when the client sent one, the exact nonce it supplied at /authorize.

func TestAuthorizationCode_FullExchange_ReturnsIDToken(t *testing.T) {
	env := setupLoginTest(t)
	client := jarClient(t)

	const nonce = "integration-test-nonce-12345"
	code, _ := authorizeAndLogin(t, env, client, appClientID, appRedirectURI, "state-idtoken",
		url.Values{"nonce": {nonce}})

	status, body := postForm(t, noRedirectClient(), tokenEndpoint(env.baseURL), url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {appClientID},
		"client_secret": {appClientSecret},
		"code":          {code},
		"redirect_uri":  {appRedirectURI},
	})
	require.Equal(t, http.StatusOK, status, "authorization_code exchange failed: %v", body)
	assert.NotEmpty(t, body["access_token"])

	idToken, ok := body["id_token"].(string)
	require.True(t, ok && idToken != "", "id_token missing from token response: %v", body)

	claims := decodeJWTClaims(t, idToken)
	assert.NotEmpty(t, claims["iss"], "iss claim missing")
	assert.NotEmpty(t, claims["sub"], "sub claim missing")
	assert.Equal(t, appClientID, claims["aud"], "aud must equal the requesting client_id")
	assert.NotEmpty(t, claims["exp"], "exp claim missing")
	assert.NotEmpty(t, claims["iat"], "iat claim missing")
	assert.Equal(t, nonce, claims["nonce"], "nonce must round-trip unchanged from the authorize request")
}

// ─── 19. Authorization Code — single use (replay protection) ─────────────────
//
// OAuth 2.1 §4.1.3 requires authorization codes to be usable exactly once.

func TestAuthorizationCode_ReuseAfterExchange_Fails(t *testing.T) {
	env := setupLoginTest(t)
	client := jarClient(t)

	code, _ := authorizeAndLogin(t, env, client, appClientID, appRedirectURI, "state-replay", nil)

	exchange := func() (int, map[string]any) {
		return postForm(t, noRedirectClient(), tokenEndpoint(env.baseURL), url.Values{
			"grant_type":    {"authorization_code"},
			"client_id":     {appClientID},
			"client_secret": {appClientSecret},
			"code":          {code},
			"redirect_uri":  {appRedirectURI},
		})
	}

	status1, body1 := exchange()
	require.Equal(t, http.StatusOK, status1, "first exchange should succeed: %v", body1)

	status2, body2 := exchange()
	assert.GreaterOrEqual(t, status2, 400, "reusing a consumed authorization code must fail")
	assert.NotEmpty(t, body2["error"])
}

// ─── 20. Authorization Code — redirect_uri mismatch at exchange ──────────────

func TestAuthorizationCode_RedirectURIMismatch_Fails(t *testing.T) {
	env := setupLoginTest(t)
	client := jarClient(t)

	code, _ := authorizeAndLogin(t, env, client, appClientID, appRedirectURI, "state-mismatch", nil)

	status, body := postForm(t, noRedirectClient(), tokenEndpoint(env.baseURL), url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {appClientID},
		"client_secret": {appClientSecret},
		"code":          {code},
		"redirect_uri":  {"http://localhost/attacker-callback"},
	})

	assert.GreaterOrEqual(t, status, 400, "exchange with a redirect_uri that doesn't match the authorize request must fail")
	assert.NotEmpty(t, body["error"])
}

// ─── 21. PKCE — public client without code_challenge is rejected ─────────────
//
// OAuth 2.1 §2.1.1 mandates PKCE for the authorization_code flow. A client
// configured with RequirePKCE=true must not be able to start a flow without
// a code_challenge.

func TestPKCE_RequiredButMissingCodeChallenge(t *testing.T) {
	env := setupLoginTest(t)
	client := jarClient(t)

	authorizeURL := fmt.Sprintf(
		"%s/oauth2/authorize?response_type=code&client_id=%s&redirect_uri=%s&scope=openid&state=state-no-pkce",
		env.baseURL, pkceClientID, url.QueryEscape(pkceRedirectURI),
	)
	status, body := getRaw(t, client, authorizeURL)

	assert.Equal(t, http.StatusBadRequest, status, "authorize without code_challenge must be rejected for a PKCE-required client, got body: %s", body)
}

// ─── 22. PKCE — full S256 flow succeeds ───────────────────────────────────────

func TestPKCE_S256FullFlow_Success(t *testing.T) {
	env := setupLoginTest(t)
	client := jarClient(t)

	verifier, challenge := genPKCEPair(t)

	code, _ := authorizeAndLogin(t, env, client, pkceClientID, pkceRedirectURI, "state-pkce-ok", url.Values{
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	})

	status, body := postForm(t, noRedirectClient(), tokenEndpoint(env.baseURL), url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {pkceClientID},
		"code":          {code},
		"redirect_uri":  {pkceRedirectURI},
		"code_verifier": {verifier},
	})

	require.Equal(t, http.StatusOK, status, "PKCE exchange with the correct verifier should succeed: %v", body)
	assert.NotEmpty(t, body["access_token"])
}

// ─── 23. PKCE — wrong code_verifier is rejected ───────────────────────────────

func TestPKCE_WrongVerifier_Fails(t *testing.T) {
	env := setupLoginTest(t)
	client := jarClient(t)

	_, challenge := genPKCEPair(t)

	code, _ := authorizeAndLogin(t, env, client, pkceClientID, pkceRedirectURI, "state-pkce-bad", url.Values{
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	})

	status, body := postForm(t, noRedirectClient(), tokenEndpoint(env.baseURL), url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {pkceClientID},
		"code":          {code},
		"redirect_uri":  {pkceRedirectURI},
		"code_verifier": {"this-does-not-match-the-challenge-at-all-0000000000"},
	})

	assert.GreaterOrEqual(t, status, 400, "PKCE exchange with a mismatched verifier must fail")
	assert.NotEmpty(t, body["error"])
}

// ─── 24. PKCE — missing code_verifier at exchange is rejected ────────────────

func TestPKCE_MissingVerifierAtExchange_Fails(t *testing.T) {
	env := setupLoginTest(t)
	client := jarClient(t)

	_, challenge := genPKCEPair(t)

	code, _ := authorizeAndLogin(t, env, client, pkceClientID, pkceRedirectURI, "state-pkce-missing", url.Values{
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	})

	status, body := postForm(t, noRedirectClient(), tokenEndpoint(env.baseURL), url.Values{
		"grant_type":   {"authorization_code"},
		"client_id":    {pkceClientID},
		"code":         {code},
		"redirect_uri": {pkceRedirectURI},
	})

	assert.GreaterOrEqual(t, status, 400, "PKCE exchange without a code_verifier must fail when the client requires PKCE")
	assert.NotEmpty(t, body["error"])
}
