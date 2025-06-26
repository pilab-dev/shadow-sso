package federation

import (
	"context"
	"errors" // Added import for errors.New
	"net/http"

	"github.com/pilab-dev/shadow-sso/domain"
	"golang.org/x/oauth2"
)

// ExternalUserInfo holds standardized user information retrieved from an external OAuth2 provider.
type ExternalUserInfo struct {
	ProviderUserID string // Unique ID of the user within the external provider (e.g., Google's 'sub')
	Email          string
	FirstName      string
	LastName       string
	Username       string // Or preferred username
	PictureURL     string
	RawData        map[string]any // Raw user data from the provider
}

// OAuth2Provider defines the interface for an external OAuth2 identity provider.
// Implementations of this interface will handle provider-specific details.
//
//go:generate go run go.uber.org/mock/mockgen -source=$GOFILE -destination=mock/mock_$GOFILE -package=mock_$GOPACKAGE OAuth2Provider
type OAuth2Provider interface {
	// Name returns the unique identifier for the provider (e.g., "google", "facebook").
	Name() string

	// GetType returns the type of the provider (e.g. "OIDC").
	GetType() domain.IdPType

	// GetOAuth2Config returns the oauth2.Config struct, initialized with the provider's
	// client ID, client secret, redirect URL, scopes, and auth/token endpoints.
	// The redirectURL parameter is the one configured in our system for this provider.
	GetOAuth2Config(redirectURL string) (*oauth2.Config, error)

	// GetAuthCodeURL generates the authorization URL the user should be redirected to.
	// It takes a state parameter for CSRF protection and the system's redirect URL.
	// It may also accept additional auth code options (e.g., PKCE parameters, nonce).
	GetAuthCodeURL(state, redirectURL string, opts ...oauth2.AuthCodeOption) (string, error)

	// ExchangeCode exchanges an authorization code for an OAuth2 token.
	ExchangeCode(ctx context.Context, redirectURL string, code string, opts ...oauth2.AuthCodeOption) (*oauth2.Token, error)

	// FetchUserInfo uses an access token to retrieve user information from the provider.
	// It returns a standardized ExternalUserInfo struct.
	FetchUserInfo(ctx context.Context, token *oauth2.Token) (*ExternalUserInfo, error)

	// GetHttpClient returns an *http.Client that can be used to make requests
	// to the provider's API, authenticated with the given token.
	GetHttpClient(ctx context.Context, token *oauth2.Token) *http.Client
}

// BaseProvider provides a common structure and partial implementation for OAuth2Provider.
// Specific providers can embed this and override methods as needed.
type BaseProvider struct {
	Config *domain.IdentityProvider // Holds the configuration loaded from the database
}

func NewBaseProvider(idpConfig *domain.IdentityProvider) *BaseProvider {
	return &BaseProvider{Config: idpConfig}
}

func (b *BaseProvider) Name() string {
	return b.Config.Name // Assumes IdP.Name is the unique key like "google", "facebook"
}

func (b *BaseProvider) GetType() domain.IdPType {
	return b.Config.Type
}

// GetOAuth2Config constructs an oauth2.Config from the stored IdP configuration.
// This method can be overridden if a provider has non-standard endpoint discovery.
func (b *BaseProvider) GetOAuth2Config(redirectURL string) (*oauth2.Config, error) {
	if b.Config.OIDCClientID == "" || b.Config.OIDCClientSecret == "" || b.Config.OIDCIssuerURL == "" {
		return nil, ErrProviderMisconfigured
	}

	// For many OIDC providers, endpoints can be discovered from the IssuerURL.
	// However, oauth2.Config requires AuthURL and TokenURL directly.
	// We'll need a mechanism to either store these explicitly in IdentityProvider
	// or discover them (e.g. using an OIDC discovery library).
	// For now, let's assume common patterns or that they might be pre-filled.
	// This part will likely need enhancement for robust OIDC endpoint discovery.

	// Placeholder: Assume IssuerURL is the base and common endpoints are appended.
	// This is NOT a robust way for all OIDC providers.
	// A proper OIDC client library would use discovery (/.well-known/openid-configuration).
	// For now, we'll assume these are correctly configured in `b.Config` or we'll construct them.
	// Let's assume OIDCIssuerURL might be the base for constructing auth/token URLs if not explicitly set.
	// This is a simplification and will be a point of extension for specific providers.
	authURL := b.Config.OIDCIssuerURL + "/auth"   // Placeholder
	tokenURL := b.Config.OIDCIssuerURL + "/token" // Placeholder

	// If specific endpoint fields exist in domain.IdentityProvider, use them.
	// For example, if we add OIDCAuthEndpointURL and OICTokenEndpointURL to domain.IdentityProvider:
	// if b.Config.OIDCAuthEndpointURL != "" { authURL = b.Config.OIDCAuthEndpointURL }
	// if b.Config.OIDCTokenEndpointURL != "" { tokenURL = b.Config.OIDCTokenEndpointURL }

	// TODO: Implement proper OIDC discovery or ensure these URLs are accurately configured.
	// For now, this is a placeholder and will likely fail for real providers without specific URLs.
	// The `golang.org/x/oauth2/google`, `.../facebook` packages often provide these endpoints.

	return &oauth2.Config{
		ClientID:     b.Config.OIDCClientID,
		ClientSecret: b.Config.OIDCClientSecret,
		RedirectURL:  redirectURL,
		Scopes:       b.Config.OIDCScopes,
		Endpoint: oauth2.Endpoint{
			AuthURL:  authURL,  // This needs to be the provider's actual authorization endpoint
			TokenURL: tokenURL, // This needs to be the provider's actual token endpoint
		},
	}, nil
}

func (b *BaseProvider) GetAuthCodeURL(state, redirectURL string, opts ...oauth2.AuthCodeOption) (string, error) {
	conf, err := b.GetOAuth2Config(redirectURL)
	if err != nil {
		return "", err
	}
	return conf.AuthCodeURL(state, opts...), nil
}

func (b *BaseProvider) ExchangeCode(ctx context.Context, redirectURL string, code string, opts ...oauth2.AuthCodeOption) (*oauth2.Token, error) {
	conf, err := b.GetOAuth2Config(redirectURL)
	if err != nil {
		return nil, err
	}
	return conf.Exchange(ctx, code, opts...)
}

func (b *BaseProvider) GetHttpClient(ctx context.Context, token *oauth2.Token) *http.Client {
	conf, err := b.GetOAuth2Config("") // RedirectURL not strictly needed for client source
	if err != nil {
		// Fallback to basic client if config fails, though this is not ideal
		return oauth2.NewClient(ctx, oauth2.StaticTokenSource(token))
	}
	return conf.Client(ctx, token)
}

// FetchUserInfo is a placeholder and MUST be implemented by each specific provider
// as the user info endpoint and response structure varies.
func (b *BaseProvider) FetchUserInfo(ctx context.Context, token *oauth2.Token) (*ExternalUserInfo, error) {
	// Example structure:
	// client := b.GetHttpClient(ctx, token)
	// resp, err := client.Get("USER_INFO_ENDPOINT_URL")
	// if err != nil { return nil, ErrFetchUserInfoFailed }
	// defer resp.Body.Close()
	// ... parse body into ExternalUserInfo ...
	return nil, errors.New("FetchUserInfo not implemented in BaseProvider; must be overridden")
}
