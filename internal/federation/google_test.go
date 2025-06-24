package federation_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/pilab-dev/shadow-sso/domain"
	"github.com/pilab-dev/shadow-sso/internal/federation"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
	googleOAuth2 "golang.org/x/oauth2/google" // Added import
)

func TestGoogleProvider_FetchUserInfo(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/oauth2/v3/userinfo") {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{
				"sub": "1234567890",
				"name": "Test User",
				"given_name": "Test",
				"family_name": "User",
				"picture": "https://example.com/avatar.jpg",
				"email": "test.user@example.com",
				"email_verified": true,
				"locale": "en"
			}`))
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	// Override the global constant for the test
	originalEndpoint := federation.GoogleUserInfoEndpoint
	federation.GoogleUserInfoEndpoint = server.URL + "/oauth2/v3/userinfo"  // Point to mock server
	defer func() { federation.GoogleUserInfoEndpoint = originalEndpoint }() // Restore

	idpConfig := &domain.IdentityProvider{
		Name:             "google",
		OIDCClientID:     "test-client-id",
		OIDCClientSecret: "test-client-secret",
		OIDCIssuerURL:    "https://accounts.google.com", // Not directly used by FetchUserInfo if endpoint is overridden
		OIDCScopes:       []string{"openid", "profile", "email"},
	}
	provider, err := federation.NewGoogleProvider(idpConfig)
	require.NoError(t, err)

	// Create a dummy token
	dummyToken := &oauth2.Token{AccessToken: "dummy-access-token"}

	userInfo, err := provider.FetchUserInfo(context.Background(), dummyToken)
	require.NoError(t, err)
	require.NotNil(t, userInfo)

	assert.Equal(t, "1234567890", userInfo.ProviderUserID)
	assert.Equal(t, "test.user@example.com", userInfo.Email)
	assert.Equal(t, "Test", userInfo.FirstName)
	assert.Equal(t, "User", userInfo.LastName)
	assert.Equal(t, "https://example.com/avatar.jpg", userInfo.PictureURL)
	assert.Equal(t, "test.user@example.com", userInfo.Username) // Falls back to email

	// Check RawData
	require.NotNil(t, userInfo.RawData)
	assert.Equal(t, "1234567890", userInfo.RawData["sub"])
	assert.Equal(t, "Test User", userInfo.RawData["name"])
	assert.Equal(t, true, userInfo.RawData["email_verified"])
}

func TestGoogleProvider_FetchUserInfo_Error(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	originalEndpoint := federation.GoogleUserInfoEndpoint
	federation.GoogleUserInfoEndpoint = server.URL // Point to mock server
	defer func() { federation.GoogleUserInfoEndpoint = originalEndpoint }()

	idpConfig := &domain.IdentityProvider{Name: "google", OIDCClientID: "id", OIDCClientSecret: "secret"}
	provider, _ := federation.NewGoogleProvider(idpConfig)
	dummyToken := &oauth2.Token{AccessToken: "dummy"}

	_, err := provider.FetchUserInfo(context.Background(), dummyToken)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to fetch user info from Google: status 500")
}

func TestNewGoogleProvider_Scopes(t *testing.T) {
	idpConfig := &domain.IdentityProvider{
		Name:       "google",
		OIDCScopes: []string{"openid", "custom_scope"},
	}
	gp, err := federation.NewGoogleProvider(idpConfig)
	require.NoError(t, err)

	assert.Contains(t, gp.Config.OIDCScopes, "openid")
	assert.Contains(t, gp.Config.OIDCScopes, "https://www.googleapis.com/auth/userinfo.profile")
	assert.Contains(t, gp.Config.OIDCScopes, "https://www.googleapis.com/auth/userinfo.email")
	assert.Contains(t, gp.Config.OIDCScopes, "custom_scope")
	assert.Len(t, gp.Config.OIDCScopes, 4) // Ensure no duplicates of default scopes if one was already there
}

func TestGoogleProvider_GetOAuth2Config(t *testing.T) {
	idpConfig := &domain.IdentityProvider{
		Name:             "google",
		OIDCClientID:     "test-client-id",
		OIDCClientSecret: "test-client-secret",
		OIDCIssuerURL:    "https://accounts.google.com",
		OIDCScopes:       []string{"openid", "email"},
	}
	provider, err := federation.NewGoogleProvider(idpConfig)
	require.NoError(t, err)

	oauthConfig, err := provider.GetOAuth2Config("http://localhost/callback/google")
	require.NoError(t, err)
	require.NotNil(t, oauthConfig)

	assert.Equal(t, "test-client-id", oauthConfig.ClientID)
	assert.Equal(t, "test-client-secret", oauthConfig.ClientSecret)
	assert.Equal(t, "http://localhost/callback/google", oauthConfig.RedirectURL)
	assert.Equal(t, googleOAuth2.Endpoint, oauthConfig.Endpoint) // Check against google's known endpoint
	assert.ElementsMatch(t, []string{"openid", "email", "https://www.googleapis.com/auth/userinfo.profile"}, oauthConfig.Scopes)
}

func TestGoogleProvider_FetchUserInfo_MalformedJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"sub": "123", "name": "Test`)) // Malformed JSON
	}))
	defer server.Close()

	originalEndpoint := federation.GoogleUserInfoEndpoint
	federation.GoogleUserInfoEndpoint = server.URL + "/userinfo"
	defer func() { federation.GoogleUserInfoEndpoint = originalEndpoint }()

	idpConfig := &domain.IdentityProvider{Name: "google", OIDCClientID: "id", OIDCClientSecret: "secret"}
	provider, _ := federation.NewGoogleProvider(idpConfig)
	dummyToken := &oauth2.Token{AccessToken: "dummy"}

	_, err := provider.FetchUserInfo(context.Background(), dummyToken)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to unmarshal Google user info")
}
