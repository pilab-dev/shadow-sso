package federation

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/pilab-dev/shadow-sso/domain"
	"golang.org/x/oauth2"
	githubOAuth2 "golang.org/x/oauth2/github"
)

var (
	GithubUserInfoEndpoint   = "https://api.github.com/user"
	GithubUserEmailsEndpoint = "https://api.github.com/user/emails"
)

// GitHubProvider implements the OAuth2Provider interface for GitHub.
type GitHubProvider struct {
	*BaseProvider
}

// NewGitHubProvider creates a new GitHubProvider.
func NewGitHubProvider(idpConfig *domain.IdentityProvider) (*GitHubProvider, error) {
	if idpConfig.Name == "" {
		idpConfig.Name = "github"
	}
	// GitHub's "issuer" isn't as standard as OIDC, but we can use its main site.
	if idpConfig.OIDCIssuerURL == "" {
		idpConfig.OIDCIssuerURL = "https://github.com"
	}

	// Ensure necessary scopes for profile information and email.
	// Common scopes for GitHub: "read:user", "user:email".
	hasReadUser := false
	hasUserEmail := false
	for _, scope := range idpConfig.OIDCScopes {
		if scope == "read:user" {
			hasReadUser = true
		}
		if scope == "user:email" {
			hasUserEmail = true
		}
	}
	if !hasReadUser {
		idpConfig.OIDCScopes = append(idpConfig.OIDCScopes, "read:user")
	}
	if !hasUserEmail {
		idpConfig.OIDCScopes = append(idpConfig.OIDCScopes, "user:email")
	}
	// Remove duplicates just in case
	seen := make(map[string]bool)
	var uniqueScopes []string
	for _, scope := range idpConfig.OIDCScopes {
		if !seen[scope] {
			seen[scope] = true
			uniqueScopes = append(uniqueScopes, scope)
		}
	}
	idpConfig.OIDCScopes = uniqueScopes

	return &GitHubProvider{
		BaseProvider: NewBaseProvider(idpConfig),
	}, nil
}

// GetOAuth2Config overrides BaseProvider's method to use GitHub's well-known endpoints.
func (g *GitHubProvider) GetOAuth2Config(redirectURL string) (*oauth2.Config, error) {
	if g.Config.OIDCClientID == "" || g.Config.OIDCClientSecret == "" {
		return nil, ErrProviderMisconfigured
	}
	return &oauth2.Config{
		ClientID:     g.Config.OIDCClientID,
		ClientSecret: g.Config.OIDCClientSecret,
		RedirectURL:  redirectURL,
		Scopes:       g.Config.OIDCScopes,
		Endpoint:     githubOAuth2.Endpoint, // Use GitHub's standard endpoint
	}, nil
}

// FetchUserInfo overrides BaseProvider's method to fetch user information from GitHub.
// GitHub requires two calls: one for user profile, another for primary email if `user:email` scope is granted.
func (g *GitHubProvider) FetchUserInfo(ctx context.Context, token *oauth2.Token) (*ExternalUserInfo, error) {
	client := g.GetHttpClient(ctx, token)

	// 1. Fetch primary user info
	userResp, err := client.Get(GithubUserInfoEndpoint)
	if err != nil {
		return nil, fmt.Errorf("github: failed to get user info: %w", err)
	}
	defer userResp.Body.Close()

	if userResp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(userResp.Body)
		return nil, fmt.Errorf("github: failed to fetch user info: status %d, body: %s", userResp.StatusCode, string(bodyBytes))
	}

	var rawUserInfo struct {
		ID        json.Number `json:"id"` // GitHub User ID is a number, but json.Number handles it flexibly
		Login     string      `json:"login"`
		Name      string      `json:"name"`
		Email     string      `json:"email"` // This email might be null or private
		AvatarURL string      `json:"avatar_url"`
		// Other fields like bio, blog, company, location etc. are available
	}

	userBody, err := io.ReadAll(userResp.Body)
	if err != nil {
		return nil, fmt.Errorf("github: failed to read user info response body: %w", err)
	}
	if err := json.Unmarshal(userBody, &rawUserInfo); err != nil {
		return nil, fmt.Errorf("github: failed to unmarshal user info: %w", err)
	}

	var rawDataMap map[string]interface{}
	_ = json.Unmarshal(userBody, &rawDataMap) // For RawData field, ignore error if it fails

	// Extract names
	firstName, lastName := g.parseName(rawUserInfo.Name)
	if rawUserInfo.Name == "" && rawUserInfo.Login != "" { // Fallback if Name is not set
		firstName = rawUserInfo.Login
	}

	// 2. Fetch user emails if `user:email` scope was granted
	primaryEmail := rawUserInfo.Email // Use the email from main user profile if available and public

	hasEmailScope := false
	for _, s := range g.Config.OIDCScopes {
		if s == "user:email" {
			hasEmailScope = true
			break
		}
	}

	if hasEmailScope {
		emailResp, err := client.Get(GithubUserEmailsEndpoint)
		if err != nil {
			// Log warning, but don't fail if primary email endpoint fails, use email from main profile if available
			// log.Printf("github: warning - failed to get user emails: %v", err)
		} else {
			defer emailResp.Body.Close()
			if emailResp.StatusCode == http.StatusOK {
				var emails []struct {
					Email    string `json:"email"`
					Primary  bool   `json:"primary"`
					Verified bool   `json:"verified"`
				}
				emailBody, _ := io.ReadAll(emailResp.Body)
				if err := json.Unmarshal(emailBody, &emails); err == nil {
					for _, e := range emails {
						if e.Primary && e.Verified {
							primaryEmail = e.Email
							break
						}
					}
					// If no primary verified email found, fallback to the first verified one
					if primaryEmail == "" || primaryEmail == rawUserInfo.Email { // if still not set or same as potentially private one
						for _, e := range emails {
							if e.Verified {
								primaryEmail = e.Email
								break
							}
						}
					}
				}
			}
		}
	}

	userIDStr := string(rawUserInfo.ID)

	return &ExternalUserInfo{
		ProviderUserID: userIDStr,
		Email:          primaryEmail,
		FirstName:      firstName,
		LastName:       lastName,
		Username:       rawUserInfo.Login, // GitHub's login is their unique username
		PictureURL:     rawUserInfo.AvatarURL,
		RawData:        rawDataMap,
	}, nil
}

func (g *GitHubProvider) parseName(fullName string) (string, string) {
	if fullName == "" {
		return "", ""
	}
	parts := strings.SplitN(fullName, " ", 2)
	if len(parts) == 1 {
		return parts[0], ""
	}
	return parts[0], parts[1]
}

// Ensure GitHubProvider implements OAuth2Provider.
var _ OAuth2Provider = (*GitHubProvider)(nil)
