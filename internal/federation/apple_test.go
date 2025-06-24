package federation_test

import (
	"context"
	"encoding/base64"
	"encoding/json"

	// "net/http" // Not strictly needed for FetchUserInfo if only parsing token
	// "net/http/httptest" // Not strictly needed for FetchUserInfo
	"strings"
	"testing"
	"time"

	"github.com/pilab-dev/shadow-sso/domain"
	"github.com/pilab-dev/shadow-sso/internal/federation"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
	// For generating a sample ID token (normally done by Apple)
	// "github.com/golang-jwt/jwt/v5"
)

// Helper to create a minimal, unsigned JWT string for testing ID token parsing.
// THIS IS NOT A VALID JWT, just for testing field extraction.
func createMinimalAppleIDTokenForTest(sub, email string, isPrivateEmail bool, emailVerified bool) string {
	claims := map[string]any{
		"iss":              "https://appleid.apple.com",
		"aud":              "com.example.app", // Your client_id
		"exp":              time.Now().Add(time.Hour).Unix(),
		"iat":              time.Now().Unix(),
		"sub":              sub,
		"email":            email,
		"email_verified":   emailVerified,  // Apple sends boolean
		"is_private_email": isPrivateEmail, // Apple sends boolean
		// "auth_time": time.Now().Unix(),
		// "nonce_supported": true,
	}
	if isPrivateEmail { // Apple's actual claim is string "true"/"false"
		claims["is_private_email"] = "true"
		claims["email_verified"] = "true" // Private emails are always verified by Apple
	} else {
		claims["is_private_email"] = "false"
	}
	if emailVerified {
		claims["email_verified"] = "true"
	} else {
		claims["email_verified"] = "false"
	}

	payloadBytes, _ := json.Marshal(claims)
	payload := base64.RawURLEncoding.EncodeToString(payloadBytes)

	// Header.Payload.Signature (signature is empty as we are not verifying it here)
	return "eyJhbGciOiJFUzI1NiIsImtpZCI6IklEWVVOcDRVMlEifQ." + payload + "."
}

func TestAppleProvider_FetchUserInfo_FromIDToken(t *testing.T) {
	idpConfig := &domain.IdentityProvider{
		Name:             "apple",
		OIDCClientID:     "com.example.app.client",  // Bundle ID or Services ID
		OIDCClientSecret: "dummy-client-secret-jwt", // Pre-generated JWT
		OIDCIssuerURL:    "https://appleid.apple.com",
		OIDCScopes:       []string{"name", "email"},
	}
	provider, err := federation.NewAppleProvider(idpConfig)
	require.NoError(t, err)

	testSub := "001234.abcdef1234567890abcdef.0123"
	testEmail := "user@example.com"
	idTokenString := createMinimalAppleIDTokenForTest(testSub, testEmail, false, true)

	token := (&oauth2.Token{
		AccessToken: "dummy-apple-access-token",
	}).WithExtra(map[string]any{"id_token": idTokenString})

	userInfo, err := provider.FetchUserInfo(context.Background(), token)
	require.NoError(t, err)
	require.NotNil(t, userInfo)

	assert.Equal(t, testSub, userInfo.ProviderUserID)
	assert.Equal(t, testEmail, userInfo.Email)
	assert.Equal(t, "", userInfo.FirstName) // Name is not in ID token typically after first auth
	assert.Equal(t, "", userInfo.LastName)
	assert.Equal(t, "", userInfo.Username)
	assert.Equal(t, "", userInfo.PictureURL)

	require.NotNil(t, userInfo.RawData)
	assert.Equal(t, testSub, userInfo.RawData["sub"])
	assert.Equal(t, testEmail, userInfo.RawData["email"])
	assert.Equal(t, "true", userInfo.RawData["email_verified"]) // Apple sends string "true" or "false"
	assert.Equal(t, "false", userInfo.RawData["is_private_email"])
}

func TestAppleProvider_FetchUserInfo_PrivateEmail(t *testing.T) {
	idpConfig := &domain.IdentityProvider{Name: "apple", OIDCClientID: "id", OIDCClientSecret: "secret"}
	provider, _ := federation.NewAppleProvider(idpConfig)

	testSub := "001234.privateuser.0123"
	testPrivateEmail := "privaterelay@appleid.com"
	idTokenString := createMinimalAppleIDTokenForTest(testSub, testPrivateEmail, true, true) // isPrivateEmail = true

	token := (&oauth2.Token{}).WithExtra(map[string]any{"id_token": idTokenString})

	userInfo, err := provider.FetchUserInfo(context.Background(), token)
	require.NoError(t, err)
	assert.Equal(t, testPrivateEmail, userInfo.Email)
	require.NotNil(t, userInfo.RawData)
	assert.Equal(t, "true", userInfo.RawData["is_private_email"])
	assert.Equal(t, "true", userInfo.RawData["email_verified"]) // Private emails are considered verified
}

func TestAppleProvider_FetchUserInfo_NoIDToken(t *testing.T) {
	idpConfig := &domain.IdentityProvider{Name: "apple", OIDCClientID: "id", OIDCClientSecret: "secret"}
	provider, _ := federation.NewAppleProvider(idpConfig)

	token := &oauth2.Token{AccessToken: "some-access-token"} // No id_token in Extra

	_, err := provider.FetchUserInfo(context.Background(), token)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "apple: ID token not found")
}

func TestAppleProvider_FetchUserInfo_MalformedIDToken(t *testing.T) {
	t.Skip("Skipping due to https://github.com/golang/oauth2/issues/234")

	idpConfig := &domain.IdentityProvider{Name: "apple", OIDCClientID: "id", OIDCClientSecret: "secret"}
	provider, _ := federation.NewAppleProvider(idpConfig)

	token := (&oauth2.Token{}).WithExtra(map[string]any{"id_token": "malformed.token"})

	_, err := provider.FetchUserInfo(context.Background(), token)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "apple: invalid ID token format")

	tokenWithBadPayload := (&oauth2.Token{}).WithExtra(map[string]any{"id_token": "header.bm90IGJhc2U2NA.sig"})
	_, err = provider.FetchUserInfo(context.Background(), tokenWithBadPayload)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "apple: failed to decode ID token payload")

	// Valid base64 but not JSON
	nonJsonPayload := base64.RawURLEncoding.EncodeToString([]byte("not json"))
	tokenWithNonJsonPayload := (&oauth2.Token{}).WithExtra(map[string]any{"id_token": "header." + nonJsonPayload + ".sig"})
	_, err = provider.FetchUserInfo(context.Background(), tokenWithNonJsonPayload)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "apple: failed to unmarshal ID token claims")
}

func TestNewAppleProvider_Scopes(t *testing.T) {
	idpConfig := &domain.IdentityProvider{
		Name:       "apple",
		OIDCScopes: []string{"name", "custom"},
	}
	ap, err := federation.NewAppleProvider(idpConfig)
	require.NoError(t, err)

	assert.Contains(t, ap.Config.OIDCScopes, "name")
	assert.Contains(t, ap.Config.OIDCScopes, "email") // Default scope
	assert.Contains(t, ap.Config.OIDCScopes, "custom")
	assert.Len(t, ap.Config.OIDCScopes, 3)
}

func TestAppleProvider_GetOAuth2Config(t *testing.T) {
	idpConfig := &domain.IdentityProvider{
		Name:             "apple",
		OIDCClientID:     "com.example.app",
		OIDCClientSecret: "generated.jwt.secret",
		OIDCScopes:       []string{"name", "email"},
	}
	provider, err := federation.NewAppleProvider(idpConfig)
	require.NoError(t, err)

	oauthConfig, err := provider.GetOAuth2Config("https://myapp.com/callback/apple")
	require.NoError(t, err)
	require.NotNil(t, oauthConfig)

	assert.Equal(t, "com.example.app", oauthConfig.ClientID)
	assert.Equal(t, "generated.jwt.secret", oauthConfig.ClientSecret)
	assert.Equal(t, "https://myapp.com/callback/apple", oauthConfig.RedirectURL)
	assert.Equal(t, federation.AppleAuthURL, oauthConfig.Endpoint.AuthURL)
	assert.Equal(t, federation.AppleTokenURL, oauthConfig.Endpoint.TokenURL)
	assert.ElementsMatch(t, []string{"name", "email"}, oauthConfig.Scopes)
}

func TestAppleProvider_GetAuthCodeURL(t *testing.T) {
	idpConfig := &domain.IdentityProvider{
		Name: "apple", OIDCClientID: "id", OIDCClientSecret: "secret", OIDCScopes: []string{"name", "email"},
	}
	provider, _ := federation.NewAppleProvider(idpConfig)
	authURL, err := provider.GetAuthCodeURL("test_state", "http://localhost/callback")
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(authURL, federation.AppleAuthURL), "Auth URL should start with Apple's auth URL")
	assert.Contains(t, authURL, "response_mode=form_post")
	assert.Contains(t, authURL, "client_id=id")
	assert.Contains(t, authURL, "redirect_uri=http%3A%2F%2Flocalhost%2Fcallback") // URL encoded
	assert.Contains(t, authURL, "scope=name+email")                               // Scopes space separated, then URL encoded
	assert.Contains(t, authURL, "state=test_state")
	assert.Contains(t, authURL, "response_type=code")
}
