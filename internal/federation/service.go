package federation

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/url"

	// Added for client.Client type
	"github.com/pilab-dev/shadow-sso/domain"
	"golang.org/x/oauth2"
)

const (
// stateCookieName is the name of the cookie used to store the OAuth2 state.
// This might be handled by the calling HTTP layer (e.g. Gin handler) rather than this service.
// stateCookieName = "sso_oauth_state"
// stateParam = "state"
// errorParam = "error"
// codeParam  = "code"
)

// Service handles the core logic for OAuth2 federation.
type Service struct {
	idpRepo            domain.IdPRepository      // To load provider configurations
	providerRegistry   map[string]OAuth2Provider // Cache for initialized providers
	defaultRedirectURL string                    // Base redirect URL for this SSO system
}

// NewService creates a new federation Service.
// defaultRedirectURL is the base URL to which providers should redirect back,
// e.g., "https://sso.example.com/federation/callback". The provider name will be appended.
func NewService(idpRepo domain.IdPRepository, defaultRedirectURL string) *Service {
	return &Service{
		idpRepo:            idpRepo,
		providerRegistry:   make(map[string]OAuth2Provider),
		defaultRedirectURL: defaultRedirectURL,
	}
}

// RegisterProvider allows specific provider implementations to be added to the service.
// This is more of a dependency injection pattern. Alternatively, providers can be constructed on-demand.
func (s *Service) RegisterProvider(provider OAuth2Provider) {
	s.providerRegistry[provider.Name()] = provider
}

// GetProvider retrieves and initializes a provider by its name.
// It first checks the registry, then tries to load and construct it from IdPRepository.
// This method needs to be expanded to instantiate specific provider types (Google, Facebook, etc.)
// based on the IdP configuration. For now, it's a placeholder for fetching from registry.
// A more dynamic approach would involve a factory pattern.
func (s *Service) GetProvider(ctx context.Context, providerName string) (OAuth2Provider, error) {
	// 1. Check registry (if using pre-registration)
	if provider, ok := s.providerRegistry[providerName]; ok {
		return provider, nil
	}

	// 2. Load IdP configuration from repository
	idpConfig, err := s.idpRepo.GetIdPByName(ctx, providerName)
	if err != nil {
		return nil, fmt.Errorf("failed to load IdP config for %s: %w", providerName, err)
	}
	if idpConfig == nil || !idpConfig.IsEnabled {
		return nil, ErrProviderNotFound
	}

	// 3. Provider Factory (Simplified)
	// Provider Factory
	switch providerName {
	case "google":
		// Ensure it's OIDC, though Google can be treated as such.
		if idpConfig.Type != domain.IdPTypeOIDC && idpConfig.Type != "" { // Allow empty type if name is "google"
			return nil, fmt.Errorf("provider 'google' is configured with incorrect type '%s', expected OIDC", idpConfig.Type)
		}
		// The NewGoogleProvider function will set defaults if some fields specific to Google are missing.
		return NewGoogleProvider(idpConfig)
	case "github":
		// GitHub isn't strictly OIDC but uses OAuth2 in a compatible way.
		// Allow empty type or OIDC type if name is "github".
		if idpConfig.Type != domain.IdPTypeOIDC && idpConfig.Type != "" {
			return nil, fmt.Errorf("provider 'github' is configured with incorrect type '%s', expected OIDC or empty", idpConfig.Type)
		}
		return NewGitHubProvider(idpConfig)
	case "facebook":
		if idpConfig.Type != domain.IdPTypeOIDC && idpConfig.Type != "" {
			return nil, fmt.Errorf("provider 'facebook' is configured with incorrect type '%s', expected OIDC or empty", idpConfig.Type)
		}
		return NewFacebookProvider(idpConfig)
	case "apple":
		if idpConfig.Type != domain.IdPTypeOIDC && idpConfig.Type != "" {
			return nil, fmt.Errorf("provider 'apple' is configured with incorrect type '%s', expected OIDC or empty", idpConfig.Type)
		}
		return NewAppleProvider(idpConfig)
	// Note: providerName for LDAP might be a specific instance name like "mycompany-ldap"
	// The type check is what matters here.
	default: // This default will now handle IdPType check
		if idpConfig.Type == domain.IdPTypeLDAP {
			// Pass nil for the client, NewLDAPProvider will use NewRealLDAPClient()
			return NewLDAPProvider(idpConfig, nil)
		}
		// Fallback to BaseProvider for generic OIDC if type matches.
		// This allows for adding other OIDC providers without specific structs,
		// assuming their user info endpoint and other details are standard enough
		// or that BaseProvider's FetchUserInfo is overridden by some other means (less likely).
		if idpConfig.Type == domain.IdPTypeOIDC {
			// Using BaseProvider directly for unknown OIDC providers has limitations:
			// 1. AuthURL/TokenURL construction in BaseProvider is a placeholder.
			//    It needs proper OIDC discovery or explicit endpoint URLs in idpConfig.
			// 2. FetchUserInfo in BaseProvider is a stub and will error.
			//    The idpConfig would need a field for UserInfoEndpointURL, and BaseProvider
			//    would need a generic way to parse the response, which is hard.
			// Therefore, using BaseProvider directly is generally not fully functional without enhancements.
			// log.Printf("Warning: Using BaseProvider for '%s'. Ensure OIDC endpoints are correctly set and FetchUserInfo might not work.", providerName)
			return NewBaseProvider(idpConfig), nil
		}
	}

	return nil, fmt.Errorf("unsupported provider: %s (type: %s)", providerName, idpConfig.Type)
}

// GenerateAuthState generates a unique, unguessable string for the state parameter.
func (s *Service) GenerateAuthState() (string, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

// GetAuthorizationURL constructs the URL to redirect the user to for authentication
// with the external provider.
func (s *Service) GetAuthorizationURL(ctx context.Context, providerName string, state string, authCodeOptions ...oauth2.AuthCodeOption) (string, error) {
	provider, err := s.GetProvider(ctx, providerName)
	if err != nil {
		return "", err
	}
	redirectURL := s.GetRedirectURLForProvider(providerName)
	return provider.GetAuthCodeURL(state, redirectURL, authCodeOptions...)
}

// HandleCallback processes the callback from the external provider.
// It exchanges the authorization code for a token and fetches user information.
// The `queryState` is the state received in the callback URL.
// The `sessionState` is the state previously stored (e.g., in a cookie) to prevent CSRF.
// `code` is the authorization code from the callback.
func (s *Service) HandleCallback(
	ctx context.Context,
	providerName string,
	queryState string,
	sessionState string, // For CSRF validation
	code string,
	authCodeOptions ...oauth2.AuthCodeOption,
) (*ExternalUserInfo, *oauth2.Token, error) {
	if queryState == "" || queryState != sessionState {
		return nil, nil, ErrInvalidAuthState
	}

	provider, err := s.GetProvider(ctx, providerName)
	if err != nil {
		return nil, nil, err
	}

	redirectURL := s.GetRedirectURLForProvider(providerName)
	token, err := provider.ExchangeCode(ctx, redirectURL, code, authCodeOptions...)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrExchangeCodeFailed, err)
	}

	userInfo, err := provider.FetchUserInfo(ctx, token)
	if err != nil {
		return nil, token, fmt.Errorf("%w: %v", ErrFetchUserInfoFailed, err)
	}

	return userInfo, token, nil
}

// GetRedirectURLForProvider constructs the specific redirect URL for a given provider.
// E.g., https://sso.example.com/federation/callback/google
func (s *Service) GetRedirectURLForProvider(providerName string) string {
	// Ensure no double slashes if defaultRedirectURL ends with / and providerName starts with /
	base := s.defaultRedirectURL
	if base[len(base)-1] == '/' {
		base = base[:len(base)-1]
	}
	return fmt.Sprintf("%s/%s", base, url.PathEscape(providerName))
}

// AuthenticateDirect handles direct authentication for providers like LDAP.
// It takes username and password, retrieves the provider configuration,
// and calls the provider's authentication method.
// It also fetches the OAuth2 client configuration for later use in attribute mapping.
func (s *Service) AuthenticateDirect(
	ctx context.Context,
	providerName string,
	username string,
	password string,
	// clientRepo is needed to fetch client-specific LDAP mappings.
	// This dependency might be better placed in the API handler that calls this,
	// or this service needs access to a ClientRepository.
	// For now, let's assume the caller (API handler) will fetch client config separately
	// after getting ExternalUserInfo. So, we only return ExternalUserInfo here.
	// If client-specific behavior within the provider becomes necessary, this might change.
) (*ExternalUserInfo, error) {
	provider, err := s.GetProvider(ctx, providerName)
	if err != nil {
		return nil, fmt.Errorf("failed to get provider '%s': %w", providerName, err)
	}

	// Check if the provider is an LDAPProvider and supports direct authentication
	ldapProvider, ok := provider.(*LDAPProvider)
	if !ok {
		return nil, fmt.Errorf("provider '%s' is not an LDAP provider or does not support direct authentication", providerName)
	}

	// Authenticate and fetch user information using the LDAP provider's specific method
	externalUser, err := ldapProvider.AuthenticateAndFetchUser(ctx, username, password)
	if err != nil {
		// Specific errors like ErrInvalidCredentials or ErrUserNotFound should be propagated
		// from the ldapProvider.AuthenticateAndFetchUser method.
		return nil, fmt.Errorf("authentication failed with provider '%s': %w", providerName, err)
	}

	return externalUser, nil
}
