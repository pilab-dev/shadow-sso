package federation_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/pilab-dev/shadow-sso/domain"
	"github.com/pilab-dev/shadow-sso/internal/federation"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
	githubOAuth2 "golang.org/x/oauth2/github"
)

func TestGitHubProvider_FetchUserInfo(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/user" { // Mock for https://api.github.com/user
			_, _ = w.Write([]byte(`{
				"id": 12345,
				"login": "testuser",
				"name": "Test User FullName",
				"email": "public_email@example.com",
				"avatar_url": "https://github.com/avatar.png"
			}`))
		} else if r.URL.Path == "/user/emails" { // Mock for https://api.github.com/user/emails
			_, _ = w.Write([]byte(`[
				{"email": "other_email@example.com", "primary": false, "verified": true},
				{"email": "primary_verified@example.com", "primary": true, "verified": true}
			]`))
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	// Override global constants for the test
	originalUserEndpoint := federation.GithubUserInfoEndpoint
	originalEmailsEndpoint := federation.GithubUserEmailsEndpoint
	federation.GithubUserInfoEndpoint = server.URL + "/user"
	federation.GithubUserEmailsEndpoint = server.URL + "/user/emails"
	defer func() {
		federation.GithubUserInfoEndpoint = originalUserEndpoint
		federation.GithubUserEmailsEndpoint = originalEmailsEndpoint
	}()

	idpConfig := &domain.IdentityProvider{
		Name:             "github",
		OIDCClientID:     "gh-client-id",
		OIDCClientSecret: "gh-client-secret",
		OIDCScopes:       []string{"read:user", "user:email"},
	}
	provider, err := federation.NewGitHubProvider(idpConfig)
	require.NoError(t, err)

	dummyToken := &oauth2.Token{AccessToken: "gh-dummy-token"}

	userInfo, err := provider.FetchUserInfo(context.Background(), dummyToken)
	require.NoError(t, err)
	require.NotNil(t, userInfo)

	assert.Equal(t, "12345", userInfo.ProviderUserID)
	assert.Equal(t, "primary_verified@example.com", userInfo.Email) // Should pick primary verified from /user/emails
	assert.Equal(t, "Test", userInfo.FirstName)
	assert.Equal(t, "User FullName", userInfo.LastName) // Corrected parsing of name
	assert.Equal(t, "testuser", userInfo.Username)
	assert.Equal(t, "https://github.com/avatar.png", userInfo.PictureURL)
	require.NotNil(t, userInfo.RawData)
	assert.Equal(t, "testuser", userInfo.RawData["login"])
}

func TestGitHubProvider_FetchUserInfo_NoName(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/user" {
			_, _ = w.Write([]byte(`{"id": 12345, "login": "testuser", "email": "onlylogin@example.com"}`)) // Name is null
		} else if r.URL.Path == "/user/emails" {
			_, _ = w.Write([]byte(`[]`)) // No other emails
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	originalUserEndpoint := federation.GithubUserInfoEndpoint
	originalEmailsEndpoint := federation.GithubUserEmailsEndpoint
	federation.GithubUserInfoEndpoint = server.URL + "/user"
	federation.GithubUserEmailsEndpoint = server.URL + "/user/emails"
	defer func() {
		// Restore values
		federation.GithubUserInfoEndpoint = originalUserEndpoint
		federation.GithubUserEmailsEndpoint = originalEmailsEndpoint
	}()

	idpConfig := &domain.IdentityProvider{Name: "github", OIDCClientID: "id", OIDCClientSecret: "secret", OIDCScopes: []string{"read:user"}}
	provider, _ := federation.NewGitHubProvider(idpConfig)
	dummyToken := &oauth2.Token{AccessToken: "dummy"}

	userInfo, err := provider.FetchUserInfo(context.Background(), dummyToken)
	require.NoError(t, err)
	assert.Equal(t, "testuser", userInfo.FirstName) // Falls back to login
	assert.Equal(t, "", userInfo.LastName)
	assert.Equal(t, "onlylogin@example.com", userInfo.Email) // Email from main profile
}

func TestGitHubProvider_FetchUserInfo_UserEndpointError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/user" {
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	defer server.Close()
	originalUserEndpoint := federation.GithubUserInfoEndpoint
	federation.GithubUserInfoEndpoint = server.URL + "/user"
	defer func() { federation.GithubUserInfoEndpoint = originalUserEndpoint }()

	idpConfig := &domain.IdentityProvider{Name: "github", OIDCClientID: "id", OIDCClientSecret: "secret"}
	provider, _ := federation.NewGitHubProvider(idpConfig)
	dummyToken := &oauth2.Token{AccessToken: "dummy"}

	_, err := provider.FetchUserInfo(context.Background(), dummyToken)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "github: failed to fetch user info: status 500")
}

func TestGitHubProvider_FetchUserInfo_EmailsEndpointError(t *testing.T) {
	// Test that FetchUserInfo still succeeds (using email from /user) if /user/emails fails
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/user" {
			_, _ = w.Write([]byte(`{"id": 123, "login": "test", "email": "user@example.com"}`))
		} else if r.URL.Path == "/user/emails" {
			w.WriteHeader(http.StatusInternalServerError) // Emails endpoint fails
		}
	}))
	defer server.Close()
	originalUserEndpoint := federation.GithubUserInfoEndpoint
	originalEmailsEndpoint := federation.GithubUserEmailsEndpoint
	federation.GithubUserInfoEndpoint = server.URL + "/user"
	federation.GithubUserEmailsEndpoint = server.URL + "/user/emails"
	defer func() {
		federation.GithubUserInfoEndpoint = originalUserEndpoint
		federation.GithubUserEmailsEndpoint = originalEmailsEndpoint
	}()

	idpConfig := &domain.IdentityProvider{Name: "github", OIDCClientID: "id", OIDCClientSecret: "secret", OIDCScopes: []string{"read:user", "user:email"}}
	provider, _ := federation.NewGitHubProvider(idpConfig)
	dummyToken := &oauth2.Token{AccessToken: "dummy"}

	userInfo, err := provider.FetchUserInfo(context.Background(), dummyToken)
	require.NoError(t, err)                             // Should not error out, just use potentially less accurate email
	assert.Equal(t, "user@example.com", userInfo.Email) // Falls back to email from /user
}

func TestNewGitHubProvider_Scopes(t *testing.T) {
	idpConfig := &domain.IdentityProvider{
		Name:       "github",
		OIDCScopes: []string{"read:user", "repo"}, // repo is a custom scope here
	}
	ghp, err := federation.NewGitHubProvider(idpConfig)
	require.NoError(t, err)

	assert.Contains(t, ghp.Config.OIDCScopes, "read:user")
	assert.Contains(t, ghp.Config.OIDCScopes, "user:email") // Default scope
	assert.Contains(t, ghp.Config.OIDCScopes, "repo")
	assert.Len(t, ghp.Config.OIDCScopes, 3)

	// Test with default scope already present
	idpConfig2 := &domain.IdentityProvider{
		Name:       "github",
		OIDCScopes: []string{"user:email"},
	}
	ghp2, err2 := federation.NewGitHubProvider(idpConfig2)
	require.NoError(t, err2)
	assert.Contains(t, ghp2.Config.OIDCScopes, "read:user")
	assert.Contains(t, ghp2.Config.OIDCScopes, "user:email")
	assert.Len(t, ghp2.Config.OIDCScopes, 2) // Should not add duplicates
}

func TestGitHubProvider_GetOAuth2Config(t *testing.T) {
	idpConfig := &domain.IdentityProvider{
		Name:             "github",
		OIDCClientID:     "gh-client-id",
		OIDCClientSecret: "gh-client-secret",
		OIDCScopes:       []string{"read:user"}, // user:email will be added by NewGitHubProvider
	}
	provider, err := federation.NewGitHubProvider(idpConfig)
	require.NoError(t, err)

	oauthConfig, err := provider.GetOAuth2Config("http://localhost/callback/github")
	require.NoError(t, err)
	require.NotNil(t, oauthConfig)

	assert.Equal(t, "gh-client-id", oauthConfig.ClientID)
	assert.Equal(t, "gh-client-secret", oauthConfig.ClientSecret)
	assert.Equal(t, "http://localhost/callback/github", oauthConfig.RedirectURL)
	assert.Equal(t, githubOAuth2.Endpoint, oauthConfig.Endpoint)
	assert.ElementsMatch(t, []string{"read:user", "user:email"}, oauthConfig.Scopes)
}
