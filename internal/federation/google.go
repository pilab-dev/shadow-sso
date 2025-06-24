package federation

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/pilab-dev/shadow-sso/domain"
	"golang.org/x/oauth2"
	googleOAuth2 "golang.org/x/oauth2/google"
)

var GoogleUserInfoEndpoint = "https://www.googleapis.com/oauth2/v3/userinfo"

// For Google, OIDC discovery (via IssuerURL "https://accounts.google.com")
// would normally provide auth and token endpoints.

// GoogleProvider implements the OAuth2Provider interface for Google.
type GoogleProvider struct {
	*BaseProvider
}

// NewGoogleProvider creates a new GoogleProvider.
// It expects an IdP configuration that has been populated with Google's specific
// ClientID, ClientSecret, and desired Scopes.
func NewGoogleProvider(idpConfig *domain.IdentityProvider) (*GoogleProvider, error) {
	if idpConfig.Name == "" { // Or a more specific check like idpConfig.ProviderType == "google"
		idpConfig.Name = "google" // Ensure name is set if creating on the fly
	}
	if idpConfig.OIDCIssuerURL == "" {
		idpConfig.OIDCIssuerURL = "https://accounts.google.com"
	}

	// Ensure necessary scopes for profile information
	hasOpenID := false
	hasProfile := false
	hasEmail := false
	for _, scope := range idpConfig.OIDCScopes {
		if scope == "openid" { // Changed from oauth2.ScopeOpenID
			hasOpenID = true
		}
		if scope == "profile" || scope == "https://www.googleapis.com/auth/userinfo.profile" {
			hasProfile = true
		}
		if scope == "email" || scope == "https://www.googleapis.com/auth/userinfo.email" {
			hasEmail = true
		}
	}
	if !hasOpenID {
		idpConfig.OIDCScopes = append(idpConfig.OIDCScopes, "openid") // Changed from oauth2.ScopeOpenID
	}
	if !hasProfile {
		idpConfig.OIDCScopes = append(idpConfig.OIDCScopes, "https://www.googleapis.com/auth/userinfo.profile")
	}
	if !hasEmail {
		idpConfig.OIDCScopes = append(idpConfig.OIDCScopes, "https://www.googleapis.com/auth/userinfo.email")
	}

	return &GoogleProvider{
		BaseProvider: NewBaseProvider(idpConfig),
	}, nil
}

// GetOAuth2Config overrides BaseProvider's method to use Google's well-known endpoints.
func (g *GoogleProvider) GetOAuth2Config(redirectURL string) (*oauth2.Config, error) {
	if g.Config.OIDCClientID == "" || g.Config.OIDCClientSecret == "" {
		return nil, ErrProviderMisconfigured
	}
	return &oauth2.Config{
		ClientID:     g.Config.OIDCClientID,
		ClientSecret: g.Config.OIDCClientSecret,
		RedirectURL:  redirectURL,
		Scopes:       g.Config.OIDCScopes,
		Endpoint:     googleOAuth2.Endpoint, // Use Google's standard endpoint
	}, nil
}

// FetchUserInfo overrides BaseProvider's method to fetch user information from Google.
func (g *GoogleProvider) FetchUserInfo(ctx context.Context, token *oauth2.Token) (*ExternalUserInfo, error) {
	client := g.GetHttpClient(ctx, token)
	resp, err := client.Get(GoogleUserInfoEndpoint)
	if err != nil {
		return nil, fmt.Errorf("failed to get user info from Google: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to fetch user info from Google: status %d, body: %s", resp.StatusCode, string(bodyBytes))
	}

	var rawUserInfo struct {
		Sub           string `json:"sub"`
		Name          string `json:"name"`
		GivenName     string `json:"given_name"`
		FamilyName    string `json:"family_name"`
		Profile       string `json:"profile"`
		Picture       string `json:"picture"`
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
		Locale        string `json:"locale"`
		HD            string `json:"hd"` // Hosted domain for G Suite users
	}

	rawBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read Google user info response body: %w", err)
	}

	if err := json.Unmarshal(rawBody, &rawUserInfo); err != nil {
		return nil, fmt.Errorf("failed to unmarshal Google user info: %w", err)
	}

	// Convert rawUserInfo to map[string]interface{} for RawData field
	var rawDataMap map[string]interface{}
	if err := json.Unmarshal(rawBody, &rawDataMap); err != nil {
		// Log this error but don't fail the whole process if main fields are parsed
		// log.Printf("Warning: could not unmarshal raw Google user data into map: %v", err)
	}

	// TODO: Consider email_verified status. For now, we take the email as is.
	// If EmailVerified is false, application might want to handle it differently.

	return &ExternalUserInfo{
		ProviderUserID: rawUserInfo.Sub,
		Email:          rawUserInfo.Email,
		FirstName:      rawUserInfo.GivenName,
		LastName:       rawUserInfo.FamilyName,
		Username:       rawUserInfo.Email, // Google doesn't have a distinct username like GitHub, email is common.
		PictureURL:     rawUserInfo.Picture,
		RawData:        rawDataMap,
	}, nil
}

// Ensure GoogleProvider implements OAuth2Provider.
var _ OAuth2Provider = (*GoogleProvider)(nil)
