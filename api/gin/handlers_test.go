//go:build gin

package sssogin

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	ssso "github.com/pilab-dev/shadow-sso"
	sssoapi "github.com/pilab-dev/shadow-sso/api"
	"github.com/pilab-dev/shadow-sso/client"
	"github.com/pilab-dev/shadow-sso/key"
	ssoerrors "github.com/pilab-dev/shadow-sso/errors" // Uncommented for error comparisons
	"github.com/stretchr/testify/assert"
)

// Mock OAuthService
type mockOAuthService struct {
	GenerateAuthCodeFunc            func(ctx context.Context, clientID, redirectURI, scope string) (string, error)
	ExchangeAuthorizationCodeFunc   func(ctx context.Context, code, clientID, clientSecret, redirectURI string) (*sssoapi.TokenResponse, error)
	RefreshTokenFunc                func(ctx context.Context, refreshToken, clientID string) (*sssoapi.TokenResponse, error)
	PasswordGrantFunc               func(ctx context.Context, username, password, scope string, cli *client.Client) (*sssoapi.TokenResponse, error)
	ClientCredentialsFunc           func(ctx context.Context, clientID, clientSecret, scope string) (*sssoapi.TokenResponse, error)
	GetUserInfoFunc                 func(ctx context.Context, token string) (*sssoapi.UserInfo, error)
	RevokeTokenFunc                 func(ctx context.Context, token, tokenTypeHint, clientID, clientSecret string) error
	IntrospectTokenFunc             func(ctx context.Context, token, tokenTypeHint, clientID, clientSecret string) (*sssoapi.IntrospectionResponse, error)
	InitiateDeviceAuthorizationFunc func(ctx context.Context, clientID, scope, verificationBaseURI string) (*sssoapi.DeviceAuthorizationResponse, error)
	IssueTokenForDeviceFlowFunc     func(ctx context.Context, deviceCode, clientID string) (*sssoapi.TokenResponse, error)
	VerifyUserCodeFunc              func(ctx context.Context, userCode, userID string) (*ssso.DeviceAuthRequest, error)
	GetJWKSFunc                     func() key.JWKS // Assuming this is where JWKS comes from for OpenID config in some tests
}

func (m *mockOAuthService) GenerateAuthCode(ctx context.Context, clientID, redirectURI, scope string) (string, error) {
	if m.GenerateAuthCodeFunc != nil {
		return m.GenerateAuthCodeFunc(ctx, clientID, redirectURI, scope)
	}
	return "", nil
}
func (m *mockOAuthService) ExchangeAuthorizationCode(ctx context.Context, code, clientID, clientSecret, redirectURI string) (*sssoapi.TokenResponse, error) {
	if m.ExchangeAuthorizationCodeFunc != nil {
		return m.ExchangeAuthorizationCodeFunc(ctx, code, clientID, clientSecret, redirectURI)
	}
	return nil, nil
}
func (m *mockOAuthService) RefreshToken(ctx context.Context, refreshTokenValue, clientID string) (*sssoapi.TokenResponse, error) {
	if m.RefreshTokenFunc != nil {
		return m.RefreshTokenFunc(ctx, refreshTokenValue, clientID)
	}
	return nil, nil
}
func (m *mockOAuthService) PasswordGrant(ctx context.Context, username, password, scope string, cli *client.Client) (*sssoapi.TokenResponse, error) {
	if m.PasswordGrantFunc != nil {
		return m.PasswordGrantFunc(ctx, username, password, scope, cli)
	}
	return nil, nil
}
func (m *mockOAuthService) ClientCredentials(ctx context.Context, clientID, clientSecret, scope string) (*sssoapi.TokenResponse, error) {
	if m.ClientCredentialsFunc != nil {
		return m.ClientCredentialsFunc(ctx, clientID, clientSecret, scope)
	}
	return nil, nil
}
func (m *mockOAuthService) GetUserInfo(ctx context.Context, token string) (*sssoapi.UserInfo, error) {
	if m.GetUserInfoFunc != nil {
		return m.GetUserInfoFunc(ctx, token)
	}
	return nil, nil
}
func (m *mockOAuthService) RevokeToken(ctx context.Context, token, tokenTypeHint, clientID, clientSecret string) error {
	if m.RevokeTokenFunc != nil {
		return m.RevokeTokenFunc(ctx, token, tokenTypeHint, clientID, clientSecret)
	}
	return nil
}
func (m *mockOAuthService) IntrospectToken(ctx context.Context, token, tokenTypeHint, clientID, clientSecret string) (*sssoapi.IntrospectionResponse, error) {
	if m.IntrospectTokenFunc != nil {
		return m.IntrospectTokenFunc(ctx, token, tokenTypeHint, clientID, clientSecret)
	}
	return nil, nil
}
func (m *mockOAuthService) InitiateDeviceAuthorization(ctx context.Context, clientID, scope, verificationBaseURI string) (*sssoapi.DeviceAuthorizationResponse, error) {
	if m.InitiateDeviceAuthorizationFunc != nil {
		return m.InitiateDeviceAuthorizationFunc(ctx, clientID, scope, verificationBaseURI)
	}
	return nil, nil
}
func (m *mockOAuthService) IssueTokenForDeviceFlow(ctx context.Context, deviceCode, clientID string) (*sssoapi.TokenResponse, error) {
	if m.IssueTokenForDeviceFlowFunc != nil {
		return m.IssueTokenForDeviceFlowFunc(ctx, deviceCode, clientID)
	}
	return nil, nil
}
func (m *mockOAuthService) VerifyUserCode(ctx context.Context, userCode, userID string) (*ssso.DeviceAuthRequest, error) {
	if m.VerifyUserCodeFunc != nil {
		return m.VerifyUserCodeFunc(ctx, userCode, userID)
	}
	return nil, nil
}
func (m *mockOAuthService) GetJWKS() key.JWKS {
	if m.GetJWKSFunc != nil {
		return m.GetJWKSFunc()
	}
	return key.JWKS{Keys: []key.JWK{}}
}

// Mock JWKSService
type mockJWKSService struct {
	GetPublicJWKSFunc func(ctx context.Context) (key.JWKS, error)
}

func (m *mockJWKSService) GetPublicJWKS(ctx context.Context) (key.JWKS, error) {
	if m.GetPublicJWKSFunc != nil {
		return m.GetPublicJWKSFunc(ctx)
	}
	return key.JWKS{Keys: []key.JWK{}}, nil
}

// Mock ClientService
type mockClientService struct {
	GetClientFunc           func(ctx context.Context, clientID string) (*client.Client, error)
	ValidateClientFunc      func(ctx context.Context, clientID, clientSecret string) (*client.Client, error)
	ValidateRedirectURIFunc func(ctx context.Context, clientID, redirectURI string) error
	ValidateScopeFunc       func(ctx context.Context, clientID string, scopes []string) error
	ValidateGrantTypeFunc   func(ctx context.Context, clientID, grantType string) error
	RequiresPKCEFunc        func(ctx context.Context, clientID string) (bool, error)
}

func (m *mockClientService) GetClient(ctx context.Context, clientID string) (*client.Client, error) {
	if m.GetClientFunc != nil {
		return m.GetClientFunc(ctx, clientID)
	}
	return &client.Client{ID: clientID}, nil // Default mock behavior
}
func (m *mockClientService) ValidateClient(ctx context.Context, clientID, clientSecret string) (*client.Client, error) {
	if m.ValidateClientFunc != nil {
		return m.ValidateClientFunc(ctx, clientID, clientSecret)
	}
	return &client.Client{ID: clientID, Secret: clientSecret}, nil // Default mock behavior
}
func (m *mockClientService) ValidateRedirectURI(ctx context.Context, clientID, redirectURI string) error {
	if m.ValidateRedirectURIFunc != nil {
		return m.ValidateRedirectURIFunc(ctx, clientID, redirectURI)
	}
	return nil
}
func (m *mockClientService) ValidateScope(ctx context.Context, clientID string, scopes []string) error {
	if m.ValidateScopeFunc != nil {
		return m.ValidateScopeFunc(ctx, clientID, scopes)
	}
	return nil
}
func (m *mockClientService) ValidateGrantType(ctx context.Context, clientID, grantType string) error {
	if m.ValidateGrantTypeFunc != nil {
		return m.ValidateGrantTypeFunc(ctx, clientID, grantType)
	}
	return nil
}
func (m *mockClientService) RequiresPKCE(ctx context.Context, clientID string) (bool, error) {
	if m.RequiresPKCEFunc != nil {
		return m.RequiresPKCEFunc(ctx, clientID)
	}
	return false, nil // Default: PKCE not required
}

// Mock PKCEService
type mockPKCEService struct {
	ValidateCodeVerifierFunc func(ctx context.Context, authCode, codeVerifier string) error
}

func (m *mockPKCEService) ValidateCodeVerifier(ctx context.Context, authCode, codeVerifier string) error {
	if m.ValidateCodeVerifierFunc != nil {
		return m.ValidateCodeVerifierFunc(ctx, authCode, codeVerifier)
	}
	return nil
}

// Helper function to set up a test Gin engine and OAuth2API
func setupTestAPI(t *testing.T) (*gin.Engine, *OAuth2API, *mockOAuthService, *mockJWKSService, *mockClientService, *mockPKCEService) {
	gin.SetMode(gin.TestMode)
	router := gin.New() // Use gin.New() instead of gin.Default() for more control in tests

	mockOAuth := &mockOAuthService{}
	mockJWKS := &mockJWKSService{}
	mockClient := &mockClientService{}
	mockPKCE := &mockPKCEService{}

	// Default OpenIDProviderConfig for testing
	// Tests that depend on specific config values will need to override this locally
	config := ssso.NewDefaultConfig("http://localhost:8080") // Base URL for testing

	api := NewOAuth2API(mockOAuth, mockJWKS, mockClient, mockPKCE, config)
	api.RegisterRoutes(router)

	return router, api, mockOAuth, mockJWKS, mockClient, mockPKCE
}

// TestMain can be used if setup/teardown for all tests in package is needed
// func TestMain(m *testing.M) {
// 	gin.SetMode(gin.TestMode)
// 	os.Exit(m.Run())
// }

// --- TODO: Implement actual tests for each handler as per the subtask description ---

func TestTokenHandler_AuthorizationCode_Success(t *testing.T) {
	router, _, mockOAuth, mockClientSvc, _, mockPKCESvc := setupTestAPI(t)

	mockClientSvc.ValidateClientFunc = func(ctx context.Context, clientID, clientSecret string) (*client.Client, error) {
		assert.Equal(t, "test-client", clientID)
		assert.Equal(t, "test-secret", clientSecret)
		return &client.Client{ID: clientID, Secret: clientSecret, GrantTypes: []string{"authorization_code"}}, nil
	}
	mockClientSvc.ValidateGrantTypeFunc = func(ctx context.Context, clientID, grantType string) error {
		assert.Equal(t, "test-client", clientID)
		assert.Equal(t, "authorization_code", grantType)
		return nil
	}
	mockClientSvc.RequiresPKCEFunc = func(ctx context.Context, clientID string) (bool, error) {
		return false, nil // PKCE not required for this test case
	}
	mockOAuth.ExchangeAuthorizationCodeFunc = func(ctx context.Context, code, clientID, clientSecret, redirectURI string) (*sssoapi.TokenResponse, error) {
		assert.Equal(t, "valid-auth-code", code)
		assert.Equal(t, "test-client", clientID)
		assert.Equal(t, "test-secret", clientSecret)
		assert.Equal(t, "http://localhost/callback", redirectURI)
		return &sssoapi.TokenResponse{
			AccessToken:  "new-access-token",
			TokenType:    "Bearer",
			ExpiresIn:    3600,
			RefreshToken: "new-refresh-token",
			IDToken:      "new-id-token",
		}, nil
	}

	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("client_id", "test-client")
	data.Set("client_secret", "test-secret")
	data.Set("code", "valid-auth-code")
	data.Set("redirect_uri", "http://localhost/callback")

	w := performPostRequest(router, "/oauth2/token", data, nil)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "no-store", w.Header().Get("Cache-Control"))
	assert.Equal(t, "no-cache", w.Header().Get("Pragma"))

	var resp sssoapi.TokenResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	assert.NoError(t, err)
	assert.Equal(t, "new-access-token", resp.AccessToken)
	assert.Equal(t, "Bearer", resp.TokenType)
}

func TestTokenHandler_InvalidClientCredentials(t *testing.T) {
	router, _, _, mockClientSvc, _, _ := setupTestAPI(t)

	mockClientSvc.ValidateClientFunc = func(ctx context.Context, clientID, clientSecret string) (*client.Client, error) {
		return nil, ssoerrors.NewInvalidClient("bad client creds")
	}

	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("client_id", "test-client")
	data.Set("client_secret", "wrong-secret")
	data.Set("code", "some-code")
	data.Set("redirect_uri", "http://localhost/callback")

	w := performPostRequest(router, "/oauth2/token", data, nil)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	var resp ssoerrors.OAuth2Error
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	assert.NoError(t, err)
	assert.Equal(t, ssoerrors.InvalidClient, resp.Code)
}

func TestTokenHandler_GrantTypeNotAllowed(t *testing.T) {
	router, _, _, mockClientSvc, _, _ := setupTestAPI(t)

	mockClientSvc.ValidateClientFunc = func(ctx context.Context, clientID, clientSecret string) (*client.Client, error) {
		return &client.Client{ID: clientID, Secret: clientSecret, GrantTypes: []string{"refresh_token"}}, nil // Does not allow authorization_code
	}
	mockClientSvc.ValidateGrantTypeFunc = func(ctx context.Context, clientID, grantType string) error {
		return ssoerrors.NewUnauthorizedClient("grant not allowed")
	}

	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("client_id", "test-client")
	data.Set("client_secret", "test-secret")
	data.Set("code", "some-code")
	data.Set("redirect_uri", "http://localhost/callback")

	w := performPostRequest(router, "/oauth2/token", data, nil)

	assert.Equal(t, http.StatusBadRequest, w.Code) // Or StatusUnauthorized depending on ssoerrors mapping
	var resp ssoerrors.OAuth2Error
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	assert.NoError(t, err)
	assert.Equal(t, ssoerrors.UnauthorizedClient, resp.Code)
}

func TestTokenHandler_UnsupportedGrantType(t *testing.T) {
	router, _, _, mockClientSvc, _, _ := setupTestAPI(t)

	mockClientSvc.ValidateClientFunc = func(ctx context.Context, clientID, clientSecret string) (*client.Client, error) {
		return &client.Client{ID: clientID, Secret: clientSecret, GrantTypes: []string{"authorization_code"}}, nil
	}
	// ValidateGrantTypeFunc might not even be called if grant type is unknown to the handler first
	// Or it might be called and then the switch default hits.
	// For this test, we'll assume it passes ValidateGrantType if it was called.
	mockClientSvc.ValidateGrantTypeFunc = func(ctx context.Context, clientID, grantType string) error {
		// This might or might not be called depending on TokenHandler's internal logic order.
		// If it is called, it should pass for this test to isolate "unsupported_grant_type".
		// However, the client's allowed grant types are checked by ValidateGrantType.
		// Let's assume client *is* allowed to use "unknown_grant_type" by some misconfiguration,
		// but the server itself doesn't support it.
		if grantType == "unknown_grant_type" {
			return nil // Client is allowed, but server switch case will fail
		}
		return ssoerrors.NewUnsupportedGrantType() // Should not happen for this path
	}

	data := url.Values{}
	data.Set("grant_type", "unknown_grant_type")
	data.Set("client_id", "test-client")
	data.Set("client_secret", "test-secret")

	w := performPostRequest(router, "/oauth2/token", data, nil)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	var resp ssoerrors.OAuth2Error
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	assert.NoError(t, err)
	assert.Equal(t, ssoerrors.UnsupportedGrantType, resp.Code)
}

func TestTokenHandler_AuthorizationCode_PKCERequired_MissingVerifier(t *testing.T) {
	router, _, _, mockClientSvc, _, _ := setupTestAPI(t)

	mockClientSvc.ValidateClientFunc = func(ctx context.Context, clientID, clientSecret string) (*client.Client, error) {
		return &client.Client{ID: clientID, GrantTypes: []string{"authorization_code"}}, nil // Public client, no secret
	}
	mockClientSvc.ValidateGrantTypeFunc = func(ctx context.Context, clientID, grantType string) error { return nil }
	mockClientSvc.RequiresPKCEFunc = func(ctx context.Context, clientID string) (bool, error) {
		return true, nil // PKCE IS required
	}
	// ExchangeAuthorizationCodeFunc will call handleAuthorizationCodeGrant, which checks for code_verifier if PKCE is required

	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("client_id", "pkce-client")
	data.Set("code", "some-auth-code")
	data.Set("redirect_uri", "http://localhost/callback")
	// Missing "code_verifier"

	w := performPostRequest(router, "/oauth2/token", data, nil)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	var resp ssoerrors.OAuth2Error
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	assert.NoError(t, err)
	assert.Equal(t, ssoerrors.PKCERequired, resp.Code) // Expecting specific PKCE error
}

func TestTokenHandler_AuthorizationCode_PKCERequired_InvalidVerifier(t *testing.T) {
	router, _, _, mockClientSvc, _, mockPKCESvc := setupTestAPI(t)

	mockClientSvc.ValidateClientFunc = func(ctx context.Context, clientID, clientSecret string) (*client.Client, error) {
		return &client.Client{ID: clientID, GrantTypes: []string{"authorization_code"}}, nil // Public client
	}
	mockClientSvc.ValidateGrantTypeFunc = func(ctx context.Context, clientID, grantType string) error { return nil }
	mockClientSvc.RequiresPKCEFunc = func(ctx context.Context, clientID string) (bool, error) {
		return true, nil // PKCE IS required
	}
	mockPKCESvc.ValidateCodeVerifierFunc = func(ctx context.Context, authCode, codeVerifier string) error {
		return ssoerrors.NewInvalidPKCE("verifier mismatch")
	}

	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("client_id", "pkce-client")
	data.Set("code", "some-auth-code")
	data.Set("redirect_uri", "http://localhost/callback")
	data.Set("code_verifier", "invalid-verifier")

	w := performPostRequest(router, "/oauth2/token", data, nil)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	var resp ssoerrors.OAuth2Error
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	assert.NoError(t, err)
	// ssoerrors.NewInvalidPKCE() creates an error with code "invalid_grant" and a description.
	// The specific error code might be ssoerrors.InvalidGrant if that's how NewInvalidPKCE is structured.
	assert.Equal(t, ssoerrors.InvalidGrant, resp.Code)
	assert.Contains(t, resp.Description, "PKCE validation failed: verifier mismatch")
}

func TestTokenHandler_RefreshToken_Success(t *testing.T) {
	router, _, mockOAuth, mockClientSvc, _, _ := setupTestAPI(t)

	mockClientSvc.ValidateClientFunc = func(ctx context.Context, clientID, clientSecret string) (*client.Client, error) {
		// For public clients, clientSecret might be empty. Adjust if your ValidateClient requires it.
		// This example assumes client_id is sufficient for a public client or client is pre-validated.
		return &client.Client{ID: clientID, GrantTypes: []string{string(GrantTypeRefreshToken)}}, nil
	}
	mockClientSvc.ValidateGrantTypeFunc = func(ctx context.Context, clientID, grantType string) error { return nil }
	mockOAuth.RefreshTokenFunc = func(ctx context.Context, refreshTokenValue, clientID string) (*sssoapi.TokenResponse, error) {
		assert.Equal(t, "valid-refresh-token", refreshTokenValue)
		assert.Equal(t, "test-client", clientID)
		return &sssoapi.TokenResponse{
			AccessToken: "new-access-token-from-refresh",
			TokenType:   "Bearer",
			ExpiresIn:   3600,
		}, nil
	}

	data := url.Values{}
	data.Set("grant_type", string(GrantTypeRefreshToken))
	data.Set("client_id", "test-client") // Required for public clients, or if client_secret not used for confidential
	data.Set("refresh_token", "valid-refresh-token")
	// No client_secret if it's a public client or if client auth is handled differently for refresh tokens

	w := performPostRequest(router, "/oauth2/token", data, nil)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp sssoapi.TokenResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	assert.NoError(t, err)
	assert.Equal(t, "new-access-token-from-refresh", resp.AccessToken)
}

func TestTokenHandler_RefreshToken_InvalidOrExpired(t *testing.T) {
	router, _, mockOAuth, mockClientSvc, _, _ := setupTestAPI(t)

	mockClientSvc.ValidateClientFunc = func(ctx context.Context, clientID, clientSecret string) (*client.Client, error) {
		return &client.Client{ID: clientID, GrantTypes: []string{string(GrantTypeRefreshToken)}}, nil
	}
	mockClientSvc.ValidateGrantTypeFunc = func(ctx context.Context, clientID, grantType string) error { return nil }
	mockOAuth.RefreshTokenFunc = func(ctx context.Context, refreshTokenValue, clientID string) (*sssoapi.TokenResponse, error) {
		return nil, ssoerrors.NewInvalidGrant("invalid refresh token")
	}

	data := url.Values{}
	data.Set("grant_type", string(GrantTypeRefreshToken))
	data.Set("client_id", "test-client")
	data.Set("refresh_token", "invalid-refresh-token")

	w := performPostRequest(router, "/oauth2/token", data, nil)

	assert.Equal(t, http.StatusBadRequest, w.Code) // As per RFC 6749, invalid_grant leads to 400
	var resp ssoerrors.OAuth2Error
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	assert.NoError(t, err)
	assert.Equal(t, ssoerrors.InvalidGrant, resp.Code)
}

func TestTokenHandler_ClientCredentials_Success(t *testing.T) {
	router, _, mockOAuth, mockClientSvc, _, _ := setupTestAPI(t)

	mockClientSvc.ValidateClientFunc = func(ctx context.Context, clientID, clientSecret string) (*client.Client, error) {
		assert.Equal(t, "confidential-client", clientID)
		assert.Equal(t, "client-super-secret", clientSecret)
		return &client.Client{ID: clientID, Secret: clientSecret, GrantTypes: []string{string(GrantTypeClientCredentials)}}, nil
	}
	mockClientSvc.ValidateGrantTypeFunc = func(ctx context.Context, clientID, grantType string) error { return nil }
	mockOAuth.ClientCredentialsFunc = func(ctx context.Context, clientID, clientSecret, scope string) (*sssoapi.TokenResponse, error) {
		assert.Equal(t, "confidential-client", clientID)
		assert.Equal(t, "client-super-secret", clientSecret)
		assert.Equal(t, "read write", scope)
		return &sssoapi.TokenResponse{
			AccessToken: "client-creds-access-token",
			TokenType:   "Bearer",
			ExpiresIn:   1800,
		}, nil
	}

	data := url.Values{}
	data.Set("grant_type", string(GrantTypeClientCredentials))
	data.Set("client_id", "confidential-client")
	data.Set("client_secret", "client-super-secret")
	data.Set("scope", "read write")

	w := performPostRequest(router, "/oauth2/token", data, nil)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp sssoapi.TokenResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	assert.NoError(t, err)
	assert.Equal(t, "client-creds-access-token", resp.AccessToken)
}

func TestTokenHandler_PasswordGrant_Success(t *testing.T) {
	router, _, mockOAuth, mockClientSvc, _, _ := setupTestAPI(t)
	expectedClient := &client.Client{ID: "test-client", Secret: "test-secret", GrantTypes: []string{string(GrantTypePassword)}}

	mockClientSvc.ValidateClientFunc = func(ctx context.Context, clientID, clientSecret string) (*client.Client, error) {
		return expectedClient, nil
	}
	mockClientSvc.ValidateGrantTypeFunc = func(ctx context.Context, clientID, grantType string) error { return nil }
	mockOAuth.PasswordGrantFunc = func(ctx context.Context, username, password, scope string, cli *client.Client) (*sssoapi.TokenResponse, error) {
		assert.Equal(t, "user", username)
		assert.Equal(t, "pass", password)
		assert.Equal(t, "profile", scope)
		assert.Equal(t, expectedClient.ID, cli.ID)
		return &sssoapi.TokenResponse{AccessToken: "password-grant-token", TokenType: "Bearer"}, nil
	}

	data := url.Values{}
	data.Set("grant_type", string(GrantTypePassword))
	data.Set("client_id", "test-client")
	data.Set("client_secret", "test-secret")
	data.Set("username", "user")
	data.Set("password", "pass")
	data.Set("scope", "profile")

	w := performPostRequest(router, "/oauth2/token", data, nil)
	assert.Equal(t, http.StatusOK, w.Code)
	var resp sssoapi.TokenResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	assert.NoError(t, err)
	assert.Equal(t, "password-grant-token", resp.AccessToken)
}

func TestTokenHandler_PasswordGrant_InvalidCredentials(t *testing.T) {
	router, _, mockOAuth, mockClientSvc, _, _ := setupTestAPI(t)
	expectedClient := &client.Client{ID: "test-client", Secret: "test-secret", GrantTypes: []string{string(GrantTypePassword)}}

	mockClientSvc.ValidateClientFunc = func(ctx context.Context, clientID, clientSecret string) (*client.Client, error) {
		return expectedClient, nil
	}
	mockClientSvc.ValidateGrantTypeFunc = func(ctx context.Context, clientID, grantType string) error { return nil }
	mockOAuth.PasswordGrantFunc = func(ctx context.Context, username, password, scope string, cli *client.Client) (*sssoapi.TokenResponse, error) {
		return nil, ssoerrors.NewInvalidGrant("invalid user credentials")
	}

	data := url.Values{}
	data.Set("grant_type", string(GrantTypePassword))
	data.Set("client_id", "test-client")
	data.Set("client_secret", "test-secret")
	data.Set("username", "user")
	data.Set("password", "wrongpass")
	data.Set("scope", "profile")

	w := performPostRequest(router, "/oauth2/token", data, nil)
	assert.Equal(t, http.StatusBadRequest, w.Code) // RFC 6749: invalid_grant -> 400
	var resp ssoerrors.OAuth2Error
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	assert.NoError(t, err)
	assert.Equal(t, ssoerrors.InvalidGrant, resp.Code)
}

func TestTokenHandler_DeviceCode_Success(t *testing.T) {
	router, _, mockOAuth, mockClientSvc, _, _ := setupTestAPI(t)
	// Device flow often uses public clients, client_secret might not be sent or validated by ValidateClient
	// TokenHandler logic: if clientSecret is empty, it calls GetClient, then checks IsConfidential.
	// For this test, assume public client, so ValidateClient is not the primary path for client auth.
	// GetClient will be called instead if client_secret is omitted.
	mockClientSvc.GetClientFunc = func(ctx context.Context, clientID string) (*client.Client, error) {
		assert.Equal(t, "device-client", clientID)
		// Simulate a public client
		return &client.Client{ID: clientID, GrantTypes: []string{string(GrantTypeDeviceCode)}}, nil
	}
	mockClientSvc.ValidateGrantTypeFunc = func(ctx context.Context, clientID, grantType string) error { return nil }
	mockOAuth.IssueTokenForDeviceFlowFunc = func(ctx context.Context, deviceCode, clientID string) (*sssoapi.TokenResponse, error) {
		assert.Equal(t, "valid-device-code", deviceCode)
		assert.Equal(t, "device-client", clientID)
		return &sssoapi.TokenResponse{AccessToken: "device-flow-token", TokenType: "Bearer"}, nil
	}

	data := url.Values{}
	data.Set("grant_type", string(GrantTypeDeviceCode))
	data.Set("client_id", "device-client") // client_id is in the body
	data.Set("device_code", "valid-device-code")

	w := performPostRequest(router, "/oauth2/token", data, nil)
	assert.Equal(t, http.StatusOK, w.Code)
	var resp sssoapi.TokenResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	assert.NoError(t, err)
	assert.Equal(t, "device-flow-token", resp.AccessToken)
}

func TestTokenHandler_DeviceCode_AuthorizationPending(t *testing.T) {
	router, _, mockOAuth, mockClientSvc, _, _ := setupTestAPI(t)
	mockClientSvc.GetClientFunc = func(ctx context.Context, clientID string) (*client.Client, error) {
		return &client.Client{ID: clientID, GrantTypes: []string{string(GrantTypeDeviceCode)}}, nil
	}
	mockClientSvc.ValidateGrantTypeFunc = func(ctx context.Context, clientID, grantType string) error { return nil }
	mockOAuth.IssueTokenForDeviceFlowFunc = func(ctx context.Context, deviceCode, clientID string) (*sssoapi.TokenResponse, error) {
		return nil, ssoerrors.ErrAuthorizationPending // This is a specific error variable
	}

	data := url.Values{}
	data.Set("grant_type", string(GrantTypeDeviceCode))
	data.Set("client_id", "device-client")
	data.Set("device_code", "pending-device-code")

	w := performPostRequest(router, "/oauth2/token", data, nil)
	assert.Equal(t, http.StatusBadRequest, w.Code) // RFC 8628: authorization_pending -> 400
	var resp ssoerrors.OAuth2Error
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	assert.NoError(t, err)
	assert.Equal(t, ssoerrors.AuthorizationPending, resp.Code) // ssoerrors.AuthorizationPending is the code string
}

func TestTokenHandler_DeviceCode_SlowDown(t *testing.T) {
	router, _, mockOAuth, mockClientSvc, _, _ := setupTestAPI(t)
	mockClientSvc.GetClientFunc = func(ctx context.Context, clientID string) (*client.Client, error) {
		return &client.Client{ID: clientID, GrantTypes: []string{string(GrantTypeDeviceCode)}}, nil
	}
	mockClientSvc.ValidateGrantTypeFunc = func(ctx context.Context, clientID, grantType string) error { return nil }
	mockOAuth.IssueTokenForDeviceFlowFunc = func(ctx context.Context, deviceCode, clientID string) (*sssoapi.TokenResponse, error) {
		return nil, ssoerrors.ErrSlowDown
	}

	data := url.Values{}
	data.Set("grant_type", string(GrantTypeDeviceCode))
	data.Set("client_id", "device-client")
	data.Set("device_code", "polling-too-fast-code")

	w := performPostRequest(router, "/oauth2/token", data, nil)
	assert.Equal(t, http.StatusBadRequest, w.Code) // RFC 8628: slow_down -> 400
	var resp ssoerrors.OAuth2Error
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	assert.NoError(t, err)
	assert.Equal(t, ssoerrors.SlowDown, resp.Code)
}

func TestTokenHandler_DeviceCode_ExpiredToken(t *testing.T) {
	router, _, mockOAuth, mockClientSvc, _, _ := setupTestAPI(t)
	mockClientSvc.GetClientFunc = func(ctx context.Context, clientID string) (*client.Client, error) {
		return &client.Client{ID: clientID, GrantTypes: []string{string(GrantTypeDeviceCode)}}, nil
	}
	mockClientSvc.ValidateGrantTypeFunc = func(ctx context.Context, clientID, grantType string) error { return nil }
	mockOAuth.IssueTokenForDeviceFlowFunc = func(ctx context.Context, deviceCode, clientID string) (*sssoapi.TokenResponse, error) {
		return nil, ssoerrors.ErrDeviceFlowTokenExpired
	}

	data := url.Values{}
	data.Set("grant_type", string(GrantTypeDeviceCode))
	data.Set("client_id", "device-client")
	data.Set("device_code", "expired-device-code")

	w := performPostRequest(router, "/oauth2/token", data, nil)
	assert.Equal(t, http.StatusBadRequest, w.Code) // RFC 8628: expired_token -> 400
	var resp ssoerrors.OAuth2Error
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	assert.NoError(t, err)
	assert.Equal(t, ssoerrors.ExpiredToken, resp.Code)
}

func TestTokenHandler_DeviceCode_AccessDenied(t *testing.T) {
	router, _, mockOAuth, mockClientSvc, _, _ := setupTestAPI(t)
	mockClientSvc.GetClientFunc = func(ctx context.Context, clientID string) (*client.Client, error) {
		return &client.Client{ID: clientID, GrantTypes: []string{string(GrantTypeDeviceCode)}}, nil
	}
	mockClientSvc.ValidateGrantTypeFunc = func(ctx context.Context, clientID, grantType string) error { return nil }
	mockOAuth.IssueTokenForDeviceFlowFunc = func(ctx context.Context, deviceCode, clientID string) (*sssoapi.TokenResponse, error) {
		return nil, ssoerrors.ErrDeviceFlowAccessDenied
	}

	data := url.Values{}
	data.Set("grant_type", string(GrantTypeDeviceCode))
	data.Set("client_id", "device-client")
	data.Set("device_code", "denied-device-code")

	w := performPostRequest(router, "/oauth2/token", data, nil)
	assert.Equal(t, http.StatusBadRequest, w.Code) // RFC 8628: access_denied -> 400
	var resp ssoerrors.OAuth2Error
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	assert.NoError(t, err)
	assert.Equal(t, ssoerrors.AccessDenied, resp.Code)
}

func TestAuthorizeHandler_Success(t *testing.T) {
	router, _, mockOAuth, mockClientSvc, _, mockPKCESvc := setupTestAPI(t)

	mockClientSvc.GetClientFunc = func(ctx context.Context, clientID string) (*client.Client, error) {
		assert.Equal(t, "test-client", clientID)
		return &client.Client{ID: clientID}, nil
	}
	mockClientSvc.ValidateRedirectURIFunc = func(ctx context.Context, clientID, redirectURI string) error {
		assert.Equal(t, "http://localhost/callback", redirectURI)
		return nil
	}
	mockClientSvc.ValidateScopeFunc = func(ctx context.Context, clientID string, scopes []string) error {
		assert.Equal(t, []string{"openid", "profile"}, scopes)
		return nil
	}
	mockClientSvc.RequiresPKCEFunc = func(ctx context.Context, clientID string) (bool, error) {
		return false, nil // PKCE not required for this simple success case
	}
	mockOAuth.GenerateAuthCodeFunc = func(ctx context.Context, clientID, redirectURI, scope string) (string, error) {
		assert.Equal(t, "test-client", clientID)
		assert.Equal(t, "http://localhost/callback", redirectURI)
		assert.Equal(t, "openid profile", scope)
		return "test-auth-code", nil
	}

	w := performGetRequest(router,
		"/oauth2/authorize?client_id=test-client&redirect_uri=http%3A%2F%2Flocalhost%2Fcallback&response_type=code&scope=openid%20profile&state=12345",
		nil,
	)

	assert.Equal(t, http.StatusFound, w.Code)
	location, err := w.Result().Location()
	assert.NoError(t, err)
	assert.Equal(t, "http://localhost/callback", location.Scheme+"://"+location.Host+location.Path)
	assert.Equal(t, "test-auth-code", location.Query().Get("code"))
	assert.Equal(t, "12345", location.Query().Get("state"))
}

func TestAuthorizeHandler_InvalidClientId(t *testing.T) {
	router, _, _, mockClientSvc, _, _ := setupTestAPI(t)
	mockClientSvc.GetClientFunc = func(ctx context.Context, clientID string) (*client.Client, error) {
		return nil, ssoerrors.NewInvalidClient("client not found")
	}

	w := performGetRequest(router,
		"/oauth2/authorize?client_id=unknown-client&redirect_uri=http%3A%2F%2Flocalhost%2Fcallback&response_type=code&scope=openid",
		nil,
	)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	var resp ssoerrors.OAuth2Error
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	assert.NoError(t, err)
	assert.Equal(t, ssoerrors.InvalidClient, resp.Code)
}

func TestAuthorizeHandler_InvalidRedirectUri(t *testing.T) {
	router, _, _, mockClientSvc, _, _ := setupTestAPI(t)
	mockClientSvc.GetClientFunc = func(ctx context.Context, clientID string) (*client.Client, error) {
		return &client.Client{ID: clientID}, nil
	}
	mockClientSvc.ValidateRedirectURIFunc = func(ctx context.Context, clientID, redirectURI string) error {
		return ssoerrors.NewInvalidRequest("redirect URI mismatch")
	}
	w := performGetRequest(router,
		"/oauth2/authorize?client_id=test-client&redirect_uri=http%3A%2F%2Fwrong%2Fcallback&response_type=code&scope=openid",
		nil,
	)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	var resp ssoerrors.OAuth2Error
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	assert.NoError(t, err)
	assert.Equal(t, ssoerrors.InvalidRequest, resp.Code) // Based on error returned by ValidateRedirectURI
}

func TestAuthorizeHandler_InvalidResponseType(t *testing.T) {
	router, _, _, mockClientSvc, _, _ := setupTestAPI(t)
	// Setup mocks for calls that happen before response_type check
	mockClientSvc.GetClientFunc = func(ctx context.Context, clientID string) (*client.Client, error) { return &client.Client{ID: clientID}, nil }
	mockClientSvc.ValidateRedirectURIFunc = func(ctx context.Context, clientID, redirectURI string) error { return nil }


	w := performGetRequest(router,
		"/oauth2/authorize?client_id=test-client&redirect_uri=http%3A%2F%2Flocalhost%2Fcallback&response_type=token&scope=openid",
		nil,
	)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	var resp ssoerrors.OAuth2Error
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	assert.NoError(t, err)
	assert.Equal(t, ssoerrors.InvalidRequest, resp.Code)
	assert.Equal(t, "Unsupported response_type", resp.Description)
}

func TestAuthorizeHandler_InvalidScope(t *testing.T) {
	router, _, _, mockClientSvc, _, _ := setupTestAPI(t)
	mockClientSvc.GetClientFunc = func(ctx context.Context, clientID string) (*client.Client, error) { return &client.Client{ID: clientID}, nil }
	mockClientSvc.ValidateRedirectURIFunc = func(ctx context.Context, clientID, redirectURI string) error { return nil }
	mockClientSvc.ValidateScopeFunc = func(ctx context.Context, clientID string, scopes []string) error {
		return ssoerrors.NewInvalidScope("disallowed scope")
	}

	w := performGetRequest(router,
		"/oauth2/authorize?client_id=test-client&redirect_uri=http%3A%2F%2Flocalhost%2Fcallback&response_type=code&scope=unknown",
		nil,
	)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	var resp ssoerrors.OAuth2Error
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	assert.NoError(t, err)
	assert.Equal(t, ssoerrors.InvalidScope, resp.Code)
}

func TestAuthorizeHandler_PKCERequired_MissingChallenge(t *testing.T) {
	router, _, _, mockClientSvc, _, _ := setupTestAPI(t)
	mockClientSvc.GetClientFunc = func(ctx context.Context, clientID string) (*client.Client, error) { return &client.Client{ID: clientID}, nil }
	mockClientSvc.ValidateRedirectURIFunc = func(ctx context.Context, clientID, redirectURI string) error { return nil }
	mockClientSvc.ValidateScopeFunc = func(ctx context.Context, clientID string, scopes []string) error { return nil }
	mockClientSvc.RequiresPKCEFunc = func(ctx context.Context, clientID string) (bool, error) {
		return true, nil // PKCE IS required
	}

	w := performGetRequest(router,
		"/oauth2/authorize?client_id=pkce-client&redirect_uri=http%3A%2F%2Flocalhost%2Fcallback&response_type=code&scope=openid",
		// Missing code_challenge and code_challenge_method
		nil,
	)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	var resp ssoerrors.OAuth2Error
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	assert.NoError(t, err)
	assert.Equal(t, ssoerrors.PKCERequired, resp.Code)
}

func TestAuthorizeHandler_PKCERequired_InvalidMethod(t *testing.T) {
	router, _, _, mockClientSvc, _, _ := setupTestAPI(t)
	mockClientSvc.GetClientFunc = func(ctx context.Context, clientID string) (*client.Client, error) { return &client.Client{ID: clientID}, nil }
	mockClientSvc.ValidateRedirectURIFunc = func(ctx context.Context, clientID, redirectURI string) error { return nil }
	mockClientSvc.ValidateScopeFunc = func(ctx context.Context, clientID string, scopes []string) error { return nil }
	mockClientSvc.RequiresPKCEFunc = func(ctx context.Context, clientID string) (bool, error) {
		return true, nil // PKCE IS required
	}

	w := performGetRequest(router,
		"/oauth2/authorize?client_id=pkce-client&redirect_uri=http%3A%2F%2Flocalhost%2Fcallback&response_type=code&scope=openid&code_challenge=testchallenge&code_challenge_method=S1", // Invalid method
		nil,
	)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	var resp ssoerrors.OAuth2Error
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	assert.NoError(t, err)
	assert.Equal(t, ssoerrors.InvalidRequest, resp.Code)
	assert.Equal(t, "Invalid code_challenge_method", resp.Description)
}

func TestUserInfoHandler_Success(t *testing.T) {
	router, _, mockOAuth, _, _, _ := setupTestAPI(t)

	expectedUserInfo := &sssoapi.UserInfo{
		Subject: "user123",
		Name:    "Test User",
		Email:   "test@example.com",
	}
	mockOAuth.GetUserInfoFunc = func(ctx context.Context, token string) (*sssoapi.UserInfo, error) {
		assert.Equal(t, "valid-bearer-token", token)
		return expectedUserInfo, nil
	}

	headers := map[string]string{"Authorization": "Bearer valid-bearer-token"}
	w := performGetRequest(router, "/oauth2/userinfo", headers)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp ui sssoapi.UserInfo
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	assert.NoError(t, err)
	assert.Equal(t, expectedUserInfo, &resp)
}

func TestUserInfoHandler_MissingToken(t *testing.T) {
	router, _, _, _, _, _ := setupTestAPI(t)

	w := performGetRequest(router, "/oauth2/userinfo", nil) // No Authorization header

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	var resp map[string]string
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	assert.NoError(t, err)
	assert.Equal(t, "missing_token", resp["error"])
}

func TestUserInfoHandler_InvalidTokenFormat_NoBearer(t *testing.T) {
	router, _, _, _, _, _ := setupTestAPI(t)

	headers := map[string]string{"Authorization": "NotBearer valid-bearer-token"}
	w := performGetRequest(router, "/oauth2/userinfo", headers)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	var resp map[string]string
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	assert.NoError(t, err)
	assert.Equal(t, "invalid_token", resp["error"])
}

func TestUserInfoHandler_InvalidTokenFormat_TooFewParts(t *testing.T) {
	router, _, _, _, _, _ := setupTestAPI(t)

	headers := map[string]string{"Authorization": "Bearer"} // Missing token part
	w := performGetRequest(router, "/oauth2/userinfo", headers)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	var resp map[string]string
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	assert.NoError(t, err)
	assert.Equal(t, "invalid_token", resp["error"])
}

func TestUserInfoHandler_ServiceError_InvalidToken(t *testing.T) {
	router, _, mockOAuth, _, _, _ := setupTestAPI(t)

	mockOAuth.GetUserInfoFunc = func(ctx context.Context, token string) (*sssoapi.UserInfo, error) {
		return nil, assert.AnError // Simulate service returning an error for the token
	}

	headers := map[string]string{"Authorization": "Bearer some-token-that-service-rejects"}
	w := performGetRequest(router, "/oauth2/userinfo", headers)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	var resp map[string]string
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	assert.NoError(t, err)
	assert.Equal(t, "invalid_token", resp["error"])
}

func TestRevokeHandler_Success(t *testing.T) {
	router, _, mockOAuth, _, _, _ := setupTestAPI(t)

	mockOAuth.RevokeTokenFunc = func(ctx context.Context, token, tokenTypeHint, clientID, clientSecret string) error {
		assert.Equal(t, "access_token_to_revoke", token)
		assert.Equal(t, "access_token", tokenTypeHint) // Example hint
		assert.Equal(t, "test-client", clientID)
		assert.Equal(t, "test-secret", clientSecret)
		return nil // Successful revocation
	}

	data := url.Values{}
	data.Set("token", "access_token_to_revoke")
	data.Set("token_type_hint", "access_token")
	data.Set("client_id", "test-client")
	data.Set("client_secret", "test-secret")

	w := performPostRequest(router, "/oauth2/revoke", data, nil)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Empty(t, w.Body.String()) // RFC 7009: response body is empty
}

func TestRevokeHandler_MissingTokenParam(t *testing.T) {
	router, _, _, _, _, _ := setupTestAPI(t)

	data := url.Values{}
	// data.Set("token", "some-token") // Token is missing
	data.Set("client_id", "test-client")
	data.Set("client_secret", "test-secret")

	w := performPostRequest(router, "/oauth2/revoke", data, nil)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	var resp ssoerrors.OAuth2Error
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	assert.NoError(t, err)
	assert.Equal(t, ssoerrors.InvalidRequest, resp.Code)
	assert.Equal(t, "token parameter is required", resp.Description)
}

func TestRevokeHandler_InvalidClientCredentials(t *testing.T) {
	router, _, mockOAuth, _, _, _ := setupTestAPI(t)

	// RevokeTokenFunc will be called with clientID and clientSecret from the form.
	// The service.RevokeToken is responsible for validating these.
	// If validation fails, it returns an *ssoerrors.OAuth2Error.
	mockOAuth.RevokeTokenFunc = func(ctx context.Context, token, tokenTypeHint, clientID, clientSecret string) error {
		return ssoerrors.NewInvalidClient("client auth failed")
	}

	data := url.Values{}
	data.Set("token", "some-token")
	data.Set("client_id", "test-client")
	data.Set("client_secret", "wrong-secret")

	w := performPostRequest(router, "/oauth2/revoke", data, nil)
	assert.Equal(t, http.StatusUnauthorized, w.Code) // Based on RevokeHandler's logic for InvalidClient
	var resp ssoerrors.OAuth2Error
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	assert.NoError(t, err)
	assert.Equal(t, ssoerrors.InvalidClient, resp.Code)
}

func TestRevokeHandler_TokenNotFound_StillReturnsOK(t *testing.T) {
	router, _, mockOAuth, _, _, _ := setupTestAPI(t)

	// Simulate the service successfully authenticating the client,
	// but then not finding the token (or it's already invalid).
	// According to RFC 7009, this should still result in a 200 OK.
	// The mockOAuth.RevokeTokenFunc for this scenario should return 'nil'
	// as the RevokeToken service method itself handles logging of "token not found"
	// but doesn't return an error for that specific case to the handler,
	// allowing the handler to return 200 OK.
	// If RevokeTokenFunc were to return, say, ssoerrors.NewInvalidToken("not found"),
	// the handler might return 400. This tests the "always 200 OK post-client-auth" idea.
	// The current sssogin.RevokeHandler returns 200 OK if err is nil.
	// If err is an ssoerrors.OAuth2Error but not InvalidClient/UnauthorizedClient, it returns 400.
	// So, to test the "token not found is OK" path, RevokeTokenFunc must return nil.
	mockOAuth.RevokeTokenFunc = func(ctx context.Context, token, tokenTypeHint, clientID, clientSecret string) error {
		// Client auth passed. Token "some-token-not-found" was processed.
		// Service internally might log "token not found" but returns nil to handler.
		return nil
	}

	data := url.Values{}
	data.Set("token", "some-token-not-found")
	data.Set("client_id", "test-client")
	data.Set("client_secret", "test-secret")

	w := performPostRequest(router, "/oauth2/revoke", data, nil)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Empty(t, w.Body.String())
}

func TestRevokeHandler_MissingClientId(t *testing.T) {
	router, _, _, _, _, _ := setupTestAPI(t)

	data := url.Values{}
	data.Set("token", "some-token")
	// client_id is missing
	data.Set("client_secret", "test-secret")

	w := performPostRequest(router, "/oauth2/revoke", data, nil)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	var resp ssoerrors.OAuth2Error
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	assert.NoError(t, err)
	assert.Equal(t, ssoerrors.InvalidRequest, resp.Code) // client_id is a required param for the handler
	assert.Equal(t, "client_id parameter is required", resp.Description)
}

func TestOpenIDConfigurationHandler_ReflectsConfig(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()

	mockOAuth := &mockOAuthService{} // Not directly used by OpenIDConfigurationHandler
	mockJWKS := &mockJWKSService{}   // Not directly used by OpenIDConfigurationHandler
	mockClient := &mockClientService{} // Not directly used
	mockPKCE := &mockPKCEService{}     // Not directly used

	// Create a specific config for this test
	testIssuer := "https://my-sso.example.com"
	config := &ssso.OpenIDProviderConfig{
		Issuer: testIssuer,
		EnabledEndpoints: ssso.EndpointsConfig{
			Authorization:       true,
			Token:               true,
			UserInfo:            true,
			JWKS:                true,
			Revocation:          true,
			Introspection:       true,
			DeviceAuthorization: true, // Enable device auth endpoint
		},
		EnabledGrantTypes: ssso.GrantTypesConfig{
			AuthorizationCode: true,
			ClientCredentials: true,
			RefreshToken:      true,
			DeviceCode:        true, // Enable device code grant
		},
		TokenConfig: ssso.TokenEndpointConfig{
			SupportedResponseTypes:       []string{"code", "custom_type"},
			SupportedResponseModes:       []string{"query", "fragment"},
			SupportedTokenEndpointAuth: []string{"client_secret_basic", "client_secret_post"},
		},
		ClaimsConfig: ssso.ClaimsGlobalConfig{
			SupportedScopes:       []string{"openid", "profile", "custom_scope"},
			SupportedClaims:       []string{"sub", "name", "email", "custom_claim"},
			EnableClaimsParameter: true,
		},
		PKCEConfig: ssso.PKCEGlobalConfig{
			Enabled:          true,
			SupportedMethods: []string{"S256"},
		},
		SecurityConfig: ssso.SecurityGlobalConfig{
			AllowedSigningAlgs:            []string{"RS256", "ES512"},
			RequireRequestURIRegistration: true,
		},
		// Other fields can be set as needed
	}

	api := NewOAuth2API(mockOAuth, mockJWKS, mockClient, mockPKCE, config)
	api.RegisterRoutes(router) // Register routes with this specific API instance

	w := performGetRequest(router, "/.well-known/openid-configuration", nil)
	assert.Equal(t, http.StatusOK, w.Code)

	var resp sssoapi.OpenIDConfiguration
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	assert.NoError(t, err)

	// Assertions based on the testConfig
	assert.Equal(t, testIssuer, resp.Issuer)
	assert.Equal(t, testIssuer+"/oauth2/authorize", resp.AuthorizationEndpoint)
	assert.Equal(t, testIssuer+"/oauth2/token", resp.TokenEndpoint)
	assert.Equal(t, testIssuer+"/oauth2/userinfo", resp.UserInfoEndpoint)
	assert.Equal(t, testIssuer+"/.well-known/jwks.json", resp.JwksURI)
	assert.NotNil(t, resp.RevocationEndpoint, "RevocationEndpoint should not be nil")
	assert.Equal(t, testIssuer+"/oauth2/revoke", *resp.RevocationEndpoint)
	assert.NotNil(t, resp.IntrospectionEndpoint, "IntrospectionEndpoint should not be nil")
	assert.Equal(t, testIssuer+"/oauth2/introspect", *resp.IntrospectionEndpoint)
	assert.NotNil(t, resp.DeviceAuthorizationEndpoint, "DeviceAuthorizationEndpoint should not be nil")
	assert.Equal(t, testIssuer+"/oauth2/device_authorization", *resp.DeviceAuthorizationEndpoint)

	assert.Contains(t, resp.GrantTypesSupported, "authorization_code")
	assert.Contains(t, resp.GrantTypesSupported, "client_credentials")
	assert.Contains(t, resp.GrantTypesSupported, "refresh_token")
	assert.Contains(t, resp.GrantTypesSupported, "urn:ietf:params:oauth:grant-type:device_code")

	assert.Equal(t, []string{"code", "custom_type"}, resp.ResponseTypesSupported)
	assert.Equal(t, []string{"query", "fragment"}, resp.ResponseModesSupported)
	assert.Equal(t, []string{"client_secret_basic", "client_secret_post"}, resp.TokenEndpointAuthMethodsSupported)

	assert.Equal(t, []string{"openid", "profile", "custom_scope"}, resp.ScopesSupported)
	assert.Equal(t, []string{"sub", "name", "email", "custom_claim"}, resp.ClaimsSupported)
	assert.True(t, resp.ClaimsParameterSupported)

	assert.Equal(t, []string{"S256"}, resp.CodeChallengeMethodsSupported)
	assert.Equal(t, []string{"RS256", "ES512"}, resp.IDTokenSigningAlgValuesSupported)
	assert.True(t, resp.RequireRequestURIRegistration)

	// Default values for fields not explicitly in OpenIDProviderConfig but set by handler
	// These might need adjustment if the OpenIDProviderConfig struct or handler defaults change.
	assert.Equal(t, []string{"public", "pairwise"}, resp.SubjectTypesSupported) // Default from handler
	assert.True(t, resp.RequestParameterSupported)    // Default from handler
	assert.True(t, resp.RequestURIParameterSupported) // Default from handler
}

func TestDeviceAuthorizationHandler_Success(t *testing.T) {
	router, api, mockOAuth, mockClientSvc, _, _ := setupTestAPI(t)
	api.config.Issuer = "https://sso.example.com" // Ensure issuer is set for verification URI

	mockClientSvc.GetClientFunc = func(ctx context.Context, clientID string) (*client.Client, error) {
		assert.Equal(t, "device-client-id", clientID)
		// Typically, device flow clients are public, but GetClient just needs to return a client.
		return &client.Client{ID: clientID, ClientType: client.ClientTypePublic}, nil
	}
	mockOAuth.InitiateDeviceAuthorizationFunc = func(ctx context.Context, clientID, scope, verificationBaseURI string) (*sssoapi.DeviceAuthorizationResponse, error) {
		assert.Equal(t, "device-client-id", clientID)
		assert.Equal(t, "device_scope", scope)
		assert.Equal(t, "https://sso.example.com", verificationBaseURI) // From api.config.Issuer
		return &sssoapi.DeviceAuthorizationResponse{
			DeviceCode:      "test-device-code",
			UserCode:        "TEST-USER-CODE",
			VerificationURI: verificationBaseURI + "/oauth2/device/verify", // As constructed by service
			VerificationURIComplete: verificationBaseURI + "/oauth2/device/verify?user_code=TEST-USER-CODE",
			ExpiresIn:       300,
			Interval:        5,
		}, nil
	}

	data := url.Values{}
	data.Set("client_id", "device-client-id")
	data.Set("scope", "device_scope")

	w := performPostRequest(router, "/oauth2/device_authorization", data, nil)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "no-store", w.Header().Get("Cache-Control"))
	assert.Equal(t, "no-cache", w.Header().Get("Pragma"))

	var resp sssoapi.DeviceAuthorizationResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	assert.NoError(t, err)
	assert.Equal(t, "test-device-code", resp.DeviceCode)
	assert.Equal(t, "TEST-USER-CODE", resp.UserCode)
	assert.Contains(t, resp.VerificationURI, "/oauth2/device/verify") // Base URI part
}

func TestDeviceAuthorizationHandler_MissingClientId(t *testing.T) {
	router, _, _, _, _, _ := setupTestAPI(t)

	data := url.Values{}
	// client_id is missing
	data.Set("scope", "device_scope")

	w := performPostRequest(router, "/oauth2/device_authorization", data, nil)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	var resp ssoerrors.OAuth2Error
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	assert.NoError(t, err)
	assert.Equal(t, ssoerrors.InvalidRequest, resp.Code)
	assert.Equal(t, "client_id is required", resp.Description)
}

func TestDeviceAuthorizationHandler_ClientNotFound(t *testing.T) {
	router, _, _, mockClientSvc, _, _ := setupTestAPI(t)

	mockClientSvc.GetClientFunc = func(ctx context.Context, clientID string) (*client.Client, error) {
		return nil, ssoerrors.NewInvalidClient("client not found for device flow")
	}
	// Note: The DeviceAuthorizationHandler calls service.InitiateDeviceAuthorization,
	// which itself calls clientService.GetClient. So, the mock for GetClient within
	// the service's call chain is what matters. The handler itself doesn't call GetClient directly.
	// This test setup needs the *service's* GetClient to fail.
	// For simplicity, we assume the service passes the error through.
	// If InitiateDeviceAuthorization handles this error and returns a different ssoerror, adjust assert.
	// The current handler calls InitiateDeviceAuthorization, which returns an error.
	// The handler then checks: if oauthErr, ok := err.(*ssoerrors.OAuth2Error); ok ...
	// So we need InitiateDeviceAuthorizationFunc to return the ssoerrors.NewInvalidClient error.

	// This mock should be on mockOAuth.InitiateDeviceAuthorizationFunc
	// For this test, let's make the service return the error directly.
	// The service's InitiateDeviceAuthorization would internally call clientService.GetClient.
	// If that fails, the service should return an appropriate error.
	// We'll mock InitiateDeviceAuthorizationFunc to simulate this.

	// Re-setting up for clarity on which mock is effective:
	routerForTest, _, mockOAuthService, _, _, _ := setupTestAPI(t)
	mockOAuthService.InitiateDeviceAuthorizationFunc = func(ctx context.Context, clientID, scope, verificationBaseURI string) (*sssoapi.DeviceAuthorizationResponse, error) {
		return nil, ssoerrors.NewInvalidClient("client not found by service")
	}


	data := url.Values{}
	data.Set("client_id", "unknown-device-client")
	data.Set("scope", "device_scope")

	w := performPostRequest(routerForTest, "/oauth2/device_authorization", data, nil)
	assert.Equal(t, http.StatusUnauthorized, w.Code) // As per handler's error mapping for InvalidClient
	var resp ssoerrors.OAuth2Error
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	assert.NoError(t, err)
	assert.Equal(t, ssoerrors.InvalidClient, resp.Code)
}

func TestDeviceAuthorizationHandler_ServiceError(t *testing.T) {
	router, _, mockOAuth, _, _, _ := setupTestAPI(t)

	mockOAuth.InitiateDeviceAuthorizationFunc = func(ctx context.Context, clientID, scope, verificationBaseURI string) (*sssoapi.DeviceAuthorizationResponse, error) {
		return nil, ssoerrors.NewServerError("internal service failure")
	}

	data := url.Values{}
	data.Set("client_id", "device-client-id")
	data.Set("scope", "device_scope")

	w := performPostRequest(router, "/oauth2/device_authorization", data, nil)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
	var resp ssoerrors.OAuth2Error
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	assert.NoError(t, err)
	assert.Equal(t, ssoerrors.ServerError, resp.Code)
}

func TestDeviceVerificationPageHandler_Success(t *testing.T) {
	router, _, _, _, _, _ := setupTestAPI(t)

	// Mocking an authenticated user
	router.Use(func(c *gin.Context) {
		c.Set("userID", "test-user-id") // Simulate authenticated user
		c.Next()
	})

	w := performGetRequest(router, "/oauth2/device/verify", nil)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "<title>Activate Device</title>")
	assert.Contains(t, w.Body.String(), `name="user_code"`)
	assert.NotContains(t, w.Body.String(), `value="PREFILL"`) // No prefill
}

func TestDeviceVerificationPageHandler_WithUserCodeQueryParam(t *testing.T) {
	router, _, _, _, _, _ := setupTestAPI(t)
	router.Use(func(c *gin.Context) {
		c.Set("userID", "test-user-id")
		c.Next()
	})

	w := performGetRequest(router, "/oauth2/device/verify?user_code=PREFILLCODE", nil)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "<title>Activate Device</title>")
	// Check that the hidden input is pre-filled and displayed
	assert.Contains(t, w.Body.String(), `name="user_code" value="PREFILLCODE"`)
	assert.Contains(t, w.Body.String(), `Code: PREFILLCODE`) // Displayed pre-filled code
}

func TestDeviceVerificationPageHandler_UserNotAuthenticated(t *testing.T) {
	router, _, _, _, _, _ := setupTestAPI(t)
	// No userID set in context

	w := performGetRequest(router, "/oauth2/device/verify", nil)
	assert.Equal(t, http.StatusUnauthorized, w.Code) // Handler returns 401
	assert.Contains(t, w.Body.String(), "You must be logged in to activate a device.")
}

func TestDeviceVerificationSubmitHandler_Success(t *testing.T) {
	router, _, mockOAuth, _, _, _ := setupTestAPI(t)
	router.Use(func(c *gin.Context) {
		c.Set("userID", "verified-user")
		c.Next()
	})

	mockOAuth.VerifyUserCodeFunc = func(ctx context.Context, userCode, userID string) (*ssso.DeviceAuthRequest, error) {
		assert.Equal(t, "GOODCODE", userCode)
		assert.Equal(t, "verified-user", userID)
		return &ssso.DeviceAuthRequest{ClientID: "some-client"}, nil
	}

	data := url.Values{}
	data.Set("user_code", "GOODCODE")
	w := performPostRequest(router, "/oauth2/device/verify", data, nil)

	assert.Equal(t, http.StatusOK, w.Code)
	bodyStr := w.Body.String()
	assert.Contains(t, bodyStr, "Device activated successfully!")
	assert.Contains(t, bodyStr, `class="message success"`)
}

func TestDeviceVerificationSubmitHandler_MissingUserCode(t *testing.T) {
	router, _, _, _, _, _ := setupTestAPI(t)
	router.Use(func(c *gin.Context) {
		c.Set("userID", "test-user")
		c.Next()
	})

	data := url.Values{}
	// user_code is missing
	w := performPostRequest(router, "/oauth2/device/verify", data, nil)

	assert.Equal(t, http.StatusOK, w.Code) // Handler returns 200 but shows error in HTML
	bodyStr := w.Body.String()
	assert.Contains(t, bodyStr, "User code cannot be empty.")
	assert.Contains(t, bodyStr, `class="message error"`)
}

func TestDeviceVerificationSubmitHandler_UserNotAuthenticated(t *testing.T) {
	router, _, _, _, _, _ := setupTestAPI(t)
	// No userID in context

	data := url.Values{}
	data.Set("user_code", "ANYCODE")
	w := performPostRequest(router, "/oauth2/device/verify", data, nil)

	assert.Equal(t, http.StatusOK, w.Code) // Handler returns 200 but shows error
	bodyStr := w.Body.String()
	assert.Contains(t, bodyStr, "Authentication required.")
	assert.Contains(t, bodyStr, `class="message error"`)
}

func TestDeviceVerificationSubmitHandler_InvalidUserCode(t *testing.T) {
	router, _, mockOAuth, _, _, _ := setupTestAPI(t)
	router.Use(func(c *gin.Context) {
		c.Set("userID", "test-user")
		c.Next()
	})

	mockOAuth.VerifyUserCodeFunc = func(ctx context.Context, userCode, userID string) (*ssso.DeviceAuthRequest, error) {
		return nil, ssoerrors.ErrUserCodeNotFound // Specific error for not found
	}

	data := url.Values{}
	data.Set("user_code", "BADCODE")
	w := performPostRequest(router, "/oauth2/device/verify", data, nil)

	assert.Equal(t, http.StatusOK, w.Code) // Handler returns 200 but shows error
	bodyStr := w.Body.String()
	assert.Contains(t, bodyStr, "Invalid or expired code.")
	assert.Contains(t, bodyStr, `class="message error"`)
}

func TestDeviceVerificationSubmitHandler_CannotApproveDeviceAuth(t *testing.T) {
	router, _, mockOAuth, _, _, _ := setupTestAPI(t)
	router.Use(func(c *gin.Context) {
		c.Set("userID", "test-user")
		c.Next()
	})

	mockOAuth.VerifyUserCodeFunc = func(ctx context.Context, userCode, userID string) (*ssso.DeviceAuthRequest, error) {
		return nil, ssoerrors.ErrCannotApproveDeviceAuth // Specific error
	}

	data := url.Values{}
	data.Set("user_code", "USEDCODE")
	w := performPostRequest(router, "/oauth2/device/verify", data, nil)

	assert.Equal(t, http.StatusOK, w.Code)
	bodyStr := w.Body.String()
	assert.Contains(t, bodyStr, "This code cannot be used.")
	assert.Contains(t, bodyStr, `class="message error"`)
}

func TestDeviceVerificationSubmitHandler_GenericServiceError(t *testing.T) {
	router, _, mockOAuth, _, _, _ := setupTestAPI(t)
	router.Use(func(c *gin.Context) {
		c.Set("userID", "test-user")
		c.Next()
	})

	mockOAuth.VerifyUserCodeFunc = func(ctx context.Context, userCode, userID string) (*ssso.DeviceAuthRequest, error) {
		return nil, assert.AnError // Generic error
	}

	data := url.Values{}
	data.Set("user_code", "ANYCODE")
	w := performPostRequest(router, "/oauth2/device/verify", data, nil)

	assert.Equal(t, http.StatusOK, w.Code)
	bodyStr := w.Body.String()
	assert.Contains(t, bodyStr, "An unexpected error occurred.")
	assert.Contains(t, bodyStr, `class="message error"`)
}

func TestIntrospectHandler_Success_ActiveToken(t *testing.T) {
	router, _, mockOAuth, _, _, _ := setupTestAPI(t)

	expectedIntrospection := &sssoapi.IntrospectionResponse{
		Active:    true,
		ClientID:  "s6BhdRkqt3",
		Username:  "john_doe",
		Scope:     "read write email",
		TokenType: "Bearer",
		ExpiresAt: time.Now().Add(time.Hour).Unix(),
		IssuedAt:  time.Now().Unix(),
		Subject:   "user123",
		Audience:  []string{"https://protected.example.net/resource"},
		Issuer:    "https://sso.example.com",
	}

	mockOAuth.IntrospectTokenFunc = func(ctx context.Context, token, tokenTypeHint, clientID, clientSecret string) (*sssoapi.IntrospectionResponse, error) {
		assert.Equal(t, "valid_token_for_introspection", token)
		assert.Equal(t, "introspect_client", clientID)
		assert.Equal(t, "introspect_secret", clientSecret)
		return expectedIntrospection, nil
	}

	data := url.Values{}
	data.Set("token", "valid_token_for_introspection")
	data.Set("client_id", "introspect_client")
	data.Set("client_secret", "introspect_secret")
	// token_type_hint is optional

	w := performPostRequest(router, "/oauth2/introspect", data, nil)
	assert.Equal(t, http.StatusOK, w.Code)

	var resp sssoapi.IntrospectionResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	assert.NoError(t, err)
	assert.True(t, resp.Active)
	assert.Equal(t, expectedIntrospection.ClientID, resp.ClientID)
	assert.Equal(t, expectedIntrospection.Username, resp.Username)
	// Other fields can be asserted as needed
}

func TestIntrospectHandler_Success_InactiveToken(t *testing.T) {
	router, _, mockOAuth, _, _, _ := setupTestAPI(t)

	mockOAuth.IntrospectTokenFunc = func(ctx context.Context, token, tokenTypeHint, clientID, clientSecret string) (*sssoapi.IntrospectionResponse, error) {
		return &sssoapi.IntrospectionResponse{Active: false}, nil
	}

	data := url.Values{}
	data.Set("token", "inactive_token")
	data.Set("client_id", "introspect_client")
	data.Set("client_secret", "introspect_secret")

	w := performPostRequest(router, "/oauth2/introspect", data, nil)
	assert.Equal(t, http.StatusOK, w.Code)
	var resp map[string]interface{} // Use map for flexibility with "active: false"
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	assert.NoError(t, err)
	assert.False(t, resp["active"].(bool))
}

func TestIntrospectHandler_TokenNotFound_ReturnsInactive(t *testing.T) {
	router, _, mockOAuth, _, _, _ := setupTestAPI(t)

	mockOAuth.IntrospectTokenFunc = func(ctx context.Context, token, tokenTypeHint, clientID, clientSecret string) (*sssoapi.IntrospectionResponse, error) {
		return nil, ssoerrors.NewInvalidRequest("token not found by service") // Service error
	}

	data := url.Values{}
	data.Set("token", "unknown_token")
	data.Set("client_id", "introspect_client")
	data.Set("client_secret", "introspect_secret")

	w := performPostRequest(router, "/oauth2/introspect", data, nil)
	assert.Equal(t, http.StatusOK, w.Code) // RFC 7662: always 200 OK if request is valid, return active:false
	var resp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	assert.NoError(t, err)
	assert.False(t, resp["active"].(bool))
}

func TestIntrospectHandler_InvalidClientCredentials(t *testing.T) {
	router, _, _, _, _, _ := setupTestAPI(t)
	// No mockOAuth needed as IntrospectHandler checks client creds first.
	// The IntrospectHandler itself does the client_id/secret check from form values.
	// If these are missing, it returns 401.
	// If service.IntrospectToken were to do client auth again, that would be different.
	// The current handler: if clientID == "" || clientSecret == "" -> 401.
	// Then calls service.IntrospectToken. That service func also validates client.

	// This test will check the handler's direct client_id/client_secret check.
	data := url.Values{}
	data.Set("token", "any_token")
	data.Set("client_id", "introspect_client")
	// client_secret is missing

	w := performPostRequest(router, "/oauth2/introspect", data, nil)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
	var resp map[string]string
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	assert.NoError(t, err)
	assert.Equal(t, "invalid_client", resp["error"])
}

func TestIntrospectHandler_MissingTokenParam(t *testing.T) {
	router, _, _, _, _, _ := setupTestAPI(t)

	data := url.Values{}
	// token is missing
	data.Set("client_id", "introspect_client")
	data.Set("client_secret", "introspect_secret")

	w := performPostRequest(router, "/oauth2/introspect", data, nil)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	var resp ssoerrors.OAuth2Error
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	assert.NoError(t, err)
	assert.Equal(t, ssoerrors.InvalidRequest, resp.Code)
	assert.Equal(t, "token parameter is required", resp.Description)
}


// Helper to make HTTP requests to the test router
func performRequest(r http.Handler, method, path string, body url.Values, headers map[string]string) *httptest.ResponseRecorder {
	var reqBody *bytes.Buffer
	if body != nil {
		reqBody = bytes.NewBufferString(body.Encode())
	} else {
		reqBody = bytes.NewBuffer(nil)
	}

	req, _ := http.NewRequest(method, path, reqBody)
	if body != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

// Helper to make GET HTTP requests to the test router
func performGetRequest(r http.Handler, path string, headers map[string]string) *httptest.ResponseRecorder {
	req, _ := http.NewRequest(http.MethodGet, path, nil)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

// Helper to make POST HTTP requests with form data to the test router
func performPostRequest(r http.Handler, path string, body url.Values, headers map[string]string) *httptest.ResponseRecorder {
	return performRequest(r, http.MethodPost, path, body, headers)
}

// Example of how a real test might look (very basic)
// func TestOpenIDConfigurationHandler_ReturnsConfig(t *testing.T) { // Keep old one commented or remove
// 	router, _, _, _, _, _ := setupTestAPI(t)

// 	w := performGetRequest(router, "/.well-known/openid-configuration", nil)

// 	assert.Equal(t, http.StatusOK, w.Code)

// 	var resp sssoapi.OpenIDConfiguration
// 	err := json.Unmarshal(w.Body.Bytes(), &resp)
// 	assert.NoError(t, err)
// 	assert.Equal(t, "http://localhost:8080", resp.Issuer) // From default config in setupTestAPI
// }
