package federation

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings" // Added import

	"github.com/pilab-dev/shadow-sso/domain"
	"golang.org/x/oauth2"
	facebookOAuth2 "golang.org/x/oauth2/facebook"
)

// Facebook's Graph API endpoint for user info.
// The fields parameter specifies what data to retrieve.
var FacebookUserInfoEndpoint = "https://graph.facebook.com/me?fields=id,name,first_name,last_name,email,picture"

// FacebookProvider implements the OAuth2Provider interface for Facebook.
type FacebookProvider struct {
	*BaseProvider
}

// NewFacebookProvider creates a new FacebookProvider.
func NewFacebookProvider(idpConfig *domain.IdentityProvider) (*FacebookProvider, error) {
	if idpConfig.Name == "" {
		idpConfig.Name = "facebook"
	}
	if idpConfig.OIDCIssuerURL == "" {
		// Facebook doesn't have a standard OIDC issuer URL in the same way Google does.
		// Its Graph API is central. We can use a placeholder or the graph API base.
		idpConfig.OIDCIssuerURL = "https://www.facebook.com" // Placeholder
	}

	// Default scopes for Facebook often include "public_profile" and "email".
	hasPublicProfile := false
	hasEmail := false
	for _, scope := range idpConfig.OIDCScopes {
		if scope == "public_profile" {
			hasPublicProfile = true
		}
		if scope == "email" {
			hasEmail = true
		}
	}
	if !hasPublicProfile {
		idpConfig.OIDCScopes = append(idpConfig.OIDCScopes, "public_profile")
	}
	if !hasEmail {
		idpConfig.OIDCScopes = append(idpConfig.OIDCScopes, "email")
	}
	// Remove duplicates
	seen := make(map[string]bool)
	var uniqueScopes []string
	for _, scope := range idpConfig.OIDCScopes {
		if !seen[scope] {
			seen[scope] = true
			uniqueScopes = append(uniqueScopes, scope)
		}
	}
	idpConfig.OIDCScopes = uniqueScopes

	return &FacebookProvider{
		BaseProvider: NewBaseProvider(idpConfig),
	}, nil
}

// GetOAuth2Config overrides BaseProvider's method to use Facebook's endpoints.
func (f *FacebookProvider) GetOAuth2Config(redirectURL string) (*oauth2.Config, error) {
	if f.Config.OIDCClientID == "" || f.Config.OIDCClientSecret == "" {
		return nil, ErrProviderMisconfigured
	}
	return &oauth2.Config{
		ClientID:     f.Config.OIDCClientID,
		ClientSecret: f.Config.OIDCClientSecret,
		RedirectURL:  redirectURL,
		Scopes:       f.Config.OIDCScopes,
		Endpoint:     facebookOAuth2.Endpoint, // Use Facebook's standard endpoint
	}, nil
}

// FetchUserInfo overrides BaseProvider's method to fetch user information from Facebook's Graph API.
func (f *FacebookProvider) FetchUserInfo(ctx context.Context, token *oauth2.Token) (*ExternalUserInfo, error) {
	// Facebook requires the appsecret_proof for server-side API calls if "Require App Secret" is enabled in App settings.
	// oauth2.Client already includes the access token in requests.
	// If appsecret_proof is needed, it's typically HMACSHA256 of access_token with app_secret.
	// For simplicity, we assume it's not strictly required or handled by the http.Client from oauth2 if token type is app.
	// The `golang.org/x/oauth2/facebook` package might handle this if the token source is configured correctly.
	// The default client obtained from `conf.Client(ctx, token)` should pass the access_token.

	client := f.GetHttpClient(ctx, token)

	// Construct the UserInfo URL with the access token, as Facebook's Graph API often expects it as a query param for /me
	// Although the HTTP client from oauth2 library usually adds it as a Bearer token header.
	// Let's rely on the client adding it as a header first. If it fails, we might need to add it as a query parameter.
	// The standard behavior for `oauth2.Client` is to use Authorization: Bearer header.

	resp, err := client.Get(FacebookUserInfoEndpoint)
	if err != nil {
		return nil, fmt.Errorf("facebook: failed to get user info: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("facebook: failed to fetch user info: status %d, body: %s", resp.StatusCode, string(bodyBytes))
	}

	var rawUserInfo struct {
		ID        string `json:"id"`
		Name      string `json:"name"` // Full name
		FirstName string `json:"first_name"`
		LastName  string `json:"last_name"`
		Email     string `json:"email"` // May be empty if user didn't grant email permission or has no email
		Picture   struct {
			Data struct {
				URL          string `json:"url"`
				IsSilhouette bool   `json:"is_silhouette"`
			} `json:"data"`
		} `json:"picture"`
	}

	rawBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("facebook: failed to read user info response body: %w", err)
	}
	if err := json.Unmarshal(rawBody, &rawUserInfo); err != nil {
		return nil, fmt.Errorf("facebook: failed to unmarshal user info: %w", err)
	}

	var rawDataMap map[string]interface{}
	_ = json.Unmarshal(rawBody, &rawDataMap)

	// Use first_name and last_name if available, otherwise parse from Name
	firstName := rawUserInfo.FirstName
	lastName := rawUserInfo.LastName
	if firstName == "" && lastName == "" && rawUserInfo.Name != "" {
		parts := strings.SplitN(rawUserInfo.Name, " ", 2)
		if len(parts) > 0 {
			firstName = parts[0]
		}
		if len(parts) > 1 {
			lastName = parts[1]
		}
	}

	pictureURL := ""
	if rawUserInfo.Picture.Data.URL != "" && !rawUserInfo.Picture.Data.IsSilhouette {
		pictureURL = rawUserInfo.Picture.Data.URL
	}

	return &ExternalUserInfo{
		ProviderUserID: rawUserInfo.ID,
		Email:          rawUserInfo.Email,
		FirstName:      firstName,
		LastName:       lastName,
		Username:       "", // Facebook doesn't have a distinct public username in the same way as GitHub
		PictureURL:     pictureURL,
		RawData:        rawDataMap,
	}, nil
}

// Ensure FacebookProvider implements OAuth2Provider.
var _ OAuth2Provider = (*FacebookProvider)(nil)
