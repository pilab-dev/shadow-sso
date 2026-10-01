package federation

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

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
//go:generate go run go.uber.org/mock/mockgen@latest -source=$GOFILE -destination=mock/mock_$GOFILE -package=mock_$GOPACKAGE OAuth2Provider
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

	discoveryMu  sync.Mutex
	discoveryDoc *oidcDiscovery
	discoveryAt  time.Time
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
// Endpoints are resolved through OIDC discovery (<issuer>/.well-known/openid-configuration).
// This method can be overridden if a provider has non-standard endpoint discovery.
func (b *BaseProvider) GetOAuth2Config(redirectURL string) (*oauth2.Config, error) {
	if b.Config.OIDCClientID == "" || b.Config.OIDCClientSecret == "" || b.Config.OIDCIssuerURL == "" {
		return nil, ErrProviderMisconfigured
	}

	doc, err := b.discover(context.Background())
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrProviderMisconfigured, err)
	}

	return &oauth2.Config{
		ClientID:     b.Config.OIDCClientID,
		ClientSecret: b.Config.OIDCClientSecret,
		RedirectURL:  redirectURL,
		Scopes:       b.Config.OIDCScopes,
		Endpoint: oauth2.Endpoint{
			AuthURL:  doc.AuthorizationEndpoint,
			TokenURL: doc.TokenEndpoint,
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

// FetchUserInfo retrieves claims from the discovered OIDC userinfo endpoint and maps the
// standard claims. Providers with non-standard responses should override it.
func (b *BaseProvider) FetchUserInfo(ctx context.Context, token *oauth2.Token) (*ExternalUserInfo, error) {
	doc, err := b.discover(ctx)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrFetchUserInfoFailed, err)
	}
	if doc.UserinfoEndpoint == "" {
		return nil, fmt.Errorf("%w: provider exposes no userinfo_endpoint", ErrFetchUserInfoFailed)
	}

	resp, err := b.GetHttpClient(ctx, token).Get(doc.UserinfoEndpoint)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrFetchUserInfoFailed, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrFetchUserInfoFailed, err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: status %d", ErrFetchUserInfoFailed, resp.StatusCode)
	}

	var claims struct {
		Sub               string `json:"sub"`
		Email             string `json:"email"`
		EmailVerified     bool   `json:"email_verified"`
		GivenName         string `json:"given_name"`
		FamilyName        string `json:"family_name"`
		PreferredUsername string `json:"preferred_username"`
		Picture           string `json:"picture"`
	}
	if err := json.Unmarshal(body, &claims); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrFetchUserInfoFailed, err)
	}
	if claims.Sub == "" {
		return nil, fmt.Errorf("%w: userinfo response has no sub claim", ErrFetchUserInfoFailed)
	}
	if claims.Email != "" && !claims.EmailVerified {
		return nil, ErrEmailNotVerified
	}

	raw := map[string]any{}
	_ = json.Unmarshal(body, &raw)

	username := claims.PreferredUsername
	if username == "" {
		username = claims.Email
	}
	return &ExternalUserInfo{
		ProviderUserID: claims.Sub,
		Email:          claims.Email,
		FirstName:      claims.GivenName,
		LastName:       claims.FamilyName,
		Username:       username,
		PictureURL:     claims.Picture,
		RawData:        raw,
	}, nil
}

// oidcDiscovery is the subset of the OIDC discovery document the provider needs.
type oidcDiscovery struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	UserinfoEndpoint      string `json:"userinfo_endpoint"`
}

const discoveryTTL = time.Hour

// discover fetches and caches the provider's discovery document.
func (b *BaseProvider) discover(ctx context.Context) (*oidcDiscovery, error) {
	b.discoveryMu.Lock()
	defer b.discoveryMu.Unlock()

	if b.discoveryDoc != nil && time.Since(b.discoveryAt) < discoveryTTL {
		return b.discoveryDoc, nil
	}

	issuer := strings.TrimRight(b.Config.OIDCIssuerURL, "/")
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, issuer+"/.well-known/openid-configuration", nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("OIDC discovery failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("OIDC discovery returned status %d", resp.StatusCode)
	}

	var doc oidcDiscovery
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&doc); err != nil {
		return nil, fmt.Errorf("invalid OIDC discovery document: %w", err)
	}
	if doc.AuthorizationEndpoint == "" || doc.TokenEndpoint == "" {
		return nil, errors.New("OIDC discovery document lacks authorization/token endpoints")
	}
	if strings.TrimRight(doc.Issuer, "/") != issuer {
		return nil, fmt.Errorf("OIDC discovery issuer mismatch: got %q, want %q", doc.Issuer, issuer)
	}

	b.discoveryDoc, b.discoveryAt = &doc, time.Now()
	return b.discoveryDoc, nil
}
