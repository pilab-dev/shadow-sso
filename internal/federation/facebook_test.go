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
	facebookOAuth2 "golang.org/x/oauth2/facebook"
)

func TestFacebookProvider_FetchUserInfo(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/me") {
			assert.Contains(t, r.URL.Query().Get("fields"), "id")
			assert.Contains(t, r.URL.Query().Get("fields"), "name")
			assert.Contains(t, r.URL.Query().Get("fields"), "first_name")
			// ... and other fields from facebookUserInfoEndpoint const

			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{
				"id": "fb-user-id-123",
				"name": "Zuck Testberg",
				"first_name": "Zuck",
				"last_name": "Testberg",
				"email": "zuck.test@example.com",
				"picture": {
					"data": {
						"height": 50,
						"is_silhouette": false,
						"url": "https://platform-lookaside.fbsbx.com/platform/profile_pic/",
						"width": 50
					}
				}
			}`))
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	originalEndpoint := federation.FacebookUserInfoEndpoint
	federation.FacebookUserInfoEndpoint = server.URL + "/me?fields=id,name,first_name,last_name,email,picture" // Adjust to match expected fields
	defer func() { federation.FacebookUserInfoEndpoint = originalEndpoint }()

	idpConfig := &domain.IdentityProvider{
		Name:             "facebook",
		OIDCClientID:     "fb-client-id",
		OIDCClientSecret: "fb-client-secret",
		OIDCScopes:       []string{"public_profile", "email"},
	}
	provider, err := federation.NewFacebookProvider(idpConfig)
	require.NoError(t, err)

	dummyToken := &oauth2.Token{AccessToken: "fb-dummy-token"}

	userInfo, err := provider.FetchUserInfo(context.Background(), dummyToken)
	require.NoError(t, err)
	require.NotNil(t, userInfo)

	assert.Equal(t, "fb-user-id-123", userInfo.ProviderUserID)
	assert.Equal(t, "zuck.test@example.com", userInfo.Email)
	assert.Equal(t, "Zuck", userInfo.FirstName)
	assert.Equal(t, "Testberg", userInfo.LastName)
	assert.Equal(t, "https://platform-lookaside.fbsbx.com/platform/profile_pic/", userInfo.PictureURL)
	assert.Equal(t, "", userInfo.Username) // Facebook doesn't have a distinct username
	require.NotNil(t, userInfo.RawData)
	assert.Equal(t, "Zuck Testberg", userInfo.RawData["name"])
}

func TestFacebookProvider_FetchUserInfo_Error(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	originalEndpoint := federation.FacebookUserInfoEndpoint
	federation.FacebookUserInfoEndpoint = server.URL + "/me?fields=id,name,first_name,last_name,email,picture"
	defer func() { federation.FacebookUserInfoEndpoint = originalEndpoint }()

	idpConfig := &domain.IdentityProvider{Name: "facebook", OIDCClientID: "id", OIDCClientSecret: "secret"}
	provider, _ := federation.NewFacebookProvider(idpConfig)
	dummyToken := &oauth2.Token{AccessToken: "dummy"}

	_, err := provider.FetchUserInfo(context.Background(), dummyToken)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "facebook: failed to fetch user info: status 500")
}

func TestNewFacebookProvider_Scopes(t *testing.T) {
	idpConfig := &domain.IdentityProvider{
		Name:       "facebook",
		OIDCScopes: []string{"user_birthday"}, // custom scope
	}
	fp, err := federation.NewFacebookProvider(idpConfig)
	require.NoError(t, err)

	assert.Contains(t, fp.Config.OIDCScopes, "public_profile")
	assert.Contains(t, fp.Config.OIDCScopes, "email")
	assert.Contains(t, fp.Config.OIDCScopes, "user_birthday")
	assert.Len(t, fp.Config.OIDCScopes, 3)

	// Test with default scope already present
	idpConfig2 := &domain.IdentityProvider{
		Name:       "facebook",
		OIDCScopes: []string{"email"},
	}
	fp2, err2 := federation.NewFacebookProvider(idpConfig2)
	require.NoError(t, err2)
	assert.Contains(t, fp2.Config.OIDCScopes, "public_profile")
	assert.Contains(t, fp2.Config.OIDCScopes, "email")
	assert.Len(t, fp2.Config.OIDCScopes, 2)
}

func TestFacebookProvider_GetOAuth2Config(t *testing.T) {
	idpConfig := &domain.IdentityProvider{
		Name:             "facebook",
		OIDCClientID:     "fb-client-id",
		OIDCClientSecret: "fb-client-secret",
		OIDCScopes:       []string{"email"}, // public_profile will be added
	}
	provider, err := federation.NewFacebookProvider(idpConfig)
	require.NoError(t, err)

	oauthConfig, err := provider.GetOAuth2Config("http://localhost/callback/facebook")
	require.NoError(t, err)
	require.NotNil(t, oauthConfig)

	assert.Equal(t, "fb-client-id", oauthConfig.ClientID)
	assert.Equal(t, "fb-client-secret", oauthConfig.ClientSecret)
	assert.Equal(t, "http://localhost/callback/facebook", oauthConfig.RedirectURL)
	assert.Equal(t, facebookOAuth2.Endpoint, oauthConfig.Endpoint)
	assert.ElementsMatch(t, []string{"email", "public_profile"}, oauthConfig.Scopes)
}
