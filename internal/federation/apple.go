package federation

import (
	"context"
	"encoding/base64" // Added for base64.RawURLEncoding
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	// "time" // Potentially needed if generating client secret JWT

	"github.com/pilab-dev/shadow-sso/domain"
	// "github.com/golang-jwt/jwt/v5" // If generating client secret JWT
	"golang.org/x/oauth2"
)

const (
	AppleAuthURL  = "https://appleid.apple.com/auth/authorize"
	AppleTokenURL = "https://appleid.apple.com/auth/token"
	// Apple does not have a standard user info endpoint like other providers.
	// User information (name, email) is primarily sent in the ID token during the initial authorization.
	// The email is only sent the first time a user authorizes an app, unless they revoke and re-authorize.
	// Name is also only sent on first authorization.
)

// AppleProvider implements the OAuth2Provider interface for Sign in with Apple.
type AppleProvider struct {
	*BaseProvider
}

// NewAppleProvider creates a new AppleProvider.
// The idpConfig.OIDCClientSecret for Apple is expected to be a pre-generated client secret JWT.
func NewAppleProvider(idpConfig *domain.IdentityProvider) (*AppleProvider, error) {
	if idpConfig.Name == "" {
		idpConfig.Name = "apple"
	}
	if idpConfig.OIDCIssuerURL == "" {
		idpConfig.OIDCIssuerURL = "https://appleid.apple.com" // Apple's issuer URL
	}

	// Default scopes for Apple: "name", "email".
	// Note: "openid" is implicit and not required to be passed by Apple.
	hasNameScope := false
	hasEmailScope := false
	for _, scope := range idpConfig.OIDCScopes {
		if scope == "name" {
			hasNameScope = true
		}
		if scope == "email" {
			hasEmailScope = true
		}
	}
	if !hasNameScope {
		idpConfig.OIDCScopes = append(idpConfig.OIDCScopes, "name")
	}
	if !hasEmailScope {
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

	return &AppleProvider{
		BaseProvider: NewBaseProvider(idpConfig),
	}, nil
}

// GetOAuth2Config overrides BaseProvider's method to use Apple's specific endpoints
// and handles the client_secret_post authentication method if the secret is a JWT.
func (a *AppleProvider) GetOAuth2Config(redirectURL string) (*oauth2.Config, error) {
	if a.Config.OIDCClientID == "" || a.Config.OIDCClientSecret == "" {
		return nil, ErrProviderMisconfigured
	}

	// The OIDCClientSecret for Apple should be the client_secret JWT.
	// The golang.org/x/oauth2 library typically sends client_id and client_secret
	// in the request body when exchanging the code if EndpointParams is not set to use basic auth.
	// Apple expects client_secret_post.

	// TODO: Implement dynamic client_secret JWT generation if needed.
	// For now, a.Config.OIDCClientSecret is assumed to be the pre-generated JWT.

	return &oauth2.Config{
		ClientID:     a.Config.OIDCClientID,     // This is your App ID (Bundle ID or Services ID)
		ClientSecret: a.Config.OIDCClientSecret, // This is the generated Client Secret JWT
		RedirectURL:  redirectURL,
		Scopes:       a.Config.OIDCScopes, // "name email"
		Endpoint: oauth2.Endpoint{
			AuthURL:  AppleAuthURL,
			TokenURL: AppleTokenURL,
			// AuthStyle: oauth2.AuthStyleInParams, // Explicitly use AuthStyleInParams if needed, though default for non-basic should be this.
		},
	}, nil
}

// ExchangeCode for Apple. The `user` form parameter may contain name info.
// The primary user info comes from the ID token.
func (a *AppleProvider) ExchangeCode(ctx context.Context, redirectURL string, code string, opts ...oauth2.AuthCodeOption) (*oauth2.Token, error) {
	conf, err := a.GetOAuth2Config(redirectURL)
	if err != nil {
		return nil, err
	}

	// Apple expects client_id and client_secret (JWT) in the POST body for token exchange.
	// The oauth2.Config.Exchange method should handle this correctly by default
	// when Endpoint.AuthStyle is not oauth2.AuthStyleInHeader (Basic Auth).
	// It defaults to sending credentials in the request body.

	token, err := conf.Exchange(ctx, code, opts...)
	if err != nil {
		// Check for specific Apple error responses if possible
		// e.g. if body contains "invalid_client" when client_secret JWT is bad
		// This often requires inspecting the raw error response if the library doesn't parse it well.
		// urlErr, ok := err.(*oauth2.RetrieveError)
		// if ok {
		//  log.Printf("Apple token exchange error response: %s", string(urlErr.Response.Body))
		// }
		return nil, fmt.Errorf("apple: failed to exchange code: %w", err)
	}

	return token, nil
}

// FetchUserInfo for Apple primarily parses the ID token.
// Apple does not have a separate userinfo endpoint that returns all details like other providers.
// Name and email are only guaranteed in the first authorization's ID token.
// The `user` POST parameter during the /auth/authorize call might also contain name info if requested with scope=name.
// This information should ideally be captured and stored locally when the user first signs up.
func (a *AppleProvider) FetchUserInfo(ctx context.Context, token *oauth2.Token) (*ExternalUserInfo, error) {
	idTokenRaw, ok := token.Extra("id_token").(string)
	if !ok || idTokenRaw == "" {
		return nil, fmt.Errorf("apple: ID token not found in token response")
	}

	// Parse the ID token (JWT). We only need the claims, not full verification here
	// as it's assumed the token exchange itself was successful with Apple's servers.
	// For production, full validation (signature, issuer, audience, expiry) is recommended.
	claims := struct {
		Sub            string `json:"sub"` // User's unique ID
		Email          string `json:"email"`
		EmailVerified  string `json:"email_verified"`   // "true" or "false" as string
		IsPrivateEmail string `json:"is_private_email"` // "true" or "false" as string, for Apple Private Email Relay
		// Name parts might not be in the ID token on subsequent logins.
		// They are typically included in the 'user' form parameter on the *initial* authorization response,
		// or potentially parsed from a nested 'name' claim in the ID token if Apple's format provides it.
		// For simplicity, we'll assume email and sub are the core pieces from ID token.
		// Actual name parsing might need to happen at the HTTP handler level from the 'user' form post.
		// For now, we'll leave name fields blank and expect them to be populated from elsewhere if available.
		// Placeholder for name if it were in ID token (Apple's structure can vary)
		// Name struct { FirstName string `json:"firstName"` LastName string `json:"lastName"`} `json:"name"`
		RawData map[string]interface{} // To store all claims
	}{}

	// Minimal JWT parsing without verification (NOT FOR PRODUCTION ID TOKEN VALIDATION)
	parts := strings.Split(idTokenRaw, ".")
	if len(parts) < 2 { // Should be 3 parts, but we only need payload
		return nil, fmt.Errorf("apple: invalid ID token format")
	}
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("apple: failed to decode ID token payload: %w", err)
	}

	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return nil, fmt.Errorf("apple: failed to unmarshal ID token claims: %w", err)
	}

	// Also unmarshal into RawData
	if err := json.Unmarshal(payloadBytes, &claims.RawData); err != nil {
		// Log warning, but proceed
		// log.Printf("Apple: Could not unmarshal ID token payload into RawData: %v", err)
	}

	// Note: Apple's `name` is typically sent in a `user` form parameter during the initial redirect from Apple to your callback.
	// It's not consistently in the ID token on subsequent authentications.
	// The application needs to capture `user` form param at callback if `scope=name` was used.
	// For now, we'll leave FirstName/LastName blank, assuming they are handled by the callback handler.
	// The `ExternalUserInfo.RawData` will contain all claims from ID token.

	// If `email_verified` is "false" or if `is_private_email` is "true", the application might
	// want to handle this with specific logic (e.g., prompt for manual verification if not verified,
	// or inform user about private relay).

	return &ExternalUserInfo{
		ProviderUserID: claims.Sub,
		Email:          claims.Email,
		FirstName:      "", // See note above, typically from 'user' form param on first auth.
		LastName:       "", // See note above.
		Username:       "", // Apple doesn't provide a username.
		PictureURL:     "", // Apple doesn't provide a picture URL via token or standard userinfo endpoint.
		RawData:        claims.RawData,
	}, nil
}

// GetAuthCodeURL for Apple needs to include response_mode="form_post" as Apple expects it.
func (a *AppleProvider) GetAuthCodeURL(state, redirectURL string, opts ...oauth2.AuthCodeOption) (string, error) {
	conf, err := a.GetOAuth2Config(redirectURL)
	if err != nil {
		return "", err
	}
	// Apple requires response_mode=form_post
	authCodeURL := conf.AuthCodeURL(state, opts...)

	parsedURL, err := url.Parse(authCodeURL)
	if err != nil {
		return "", fmt.Errorf("apple: failed to parse auth code URL: %w", err)
	}
	queryParams := parsedURL.Query()
	if queryParams.Get("response_mode") == "" {
		queryParams.Set("response_mode", "form_post")
	}
	parsedURL.RawQuery = queryParams.Encode()

	return parsedURL.String(), nil
}

// Ensure AppleProvider implements OAuth2Provider.
var _ OAuth2Provider = (*AppleProvider)(nil)
