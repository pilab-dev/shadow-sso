//nolint:varnamelen,tagliatelle
package ssso

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/labstack/echo/v4"
	"github.com/pilab-dev/shadow-sso/client"
	"github.com/pilab-dev/shadow-sso/errors"
	"github.com/rs/zerolog/log"
)

// OAuth2API struct to hold dependencies
type OAuth2API struct {
	service       *OAuthService
	jwksService   *JWKSService
	clientService *client.ClientService
	pkceService   *PKCEService
	config        *OpenIDProviderConfig
}

// NewOAuth2API initializes the OAuth2 API
func NewOAuth2API(
	service *OAuthService,
	jwksService *JWKSService,
	clientService *client.ClientService,
	pkceService *PKCEService,
	config *OpenIDProviderConfig,
) *OAuth2API {
	if config == nil {
		config = NewDefaultConfig("https://your-default-issuer.com")
	}
	return &OAuth2API{
		service:       service,
		jwksService:   jwksService,
		clientService: clientService,
		pkceService:   pkceService,
		config:        config,
	}
}

// RegisterRoutes registers the OAuth2 routes
func (api *OAuth2API) RegisterRoutes(e *echo.Echo) {
	e.POST("/oauth2/token", api.TokenHandler)
	e.GET("/oauth2/authorize", api.AuthorizeHandler)
	e.GET("/oauth2/userinfo", api.UserInfoHandler)
	e.POST("/oauth2/revoke", api.RevokeHandler)

	// OpenID Configuration endpoints
	e.GET("/.well-known/openid-configuration", api.OpenIDConfigurationHandler)
	e.GET("/.well-known/jwks.json", api.JWKSHandler)
}

// AuthorizeHandler handles OAuth 2.0 authorization requests. It validates the client, redirect URI,
// response type, scope, and PKCE (Proof Key for Code Exchange) requirements. If all validations pass,
// it generates an authorization code and redirects the user to the provided redirect URI with the code.
func (api *OAuth2API) AuthorizeHandler(c echo.Context) error {
	clientID := c.QueryParam("client_id")
	redirectURI := c.QueryParam("redirect_uri")
	responseType := c.QueryParam("response_type")
	scope := c.QueryParam("scope")
	state := c.QueryParam("state")

	// Validate client
	_, err := api.clientService.GetClient(c.Request().Context(), clientID)
	if err != nil {
		return c.JSON(http.StatusBadRequest, errors.NewInvalidClient("Invalid client_id"))
	}

	// Validate redirect URI
	if err := api.clientService.ValidateRedirectURI(c.Request().Context(), clientID, redirectURI); err != nil {
		return c.JSON(http.StatusBadRequest, errors.NewInvalidRequest("Invalid redirect_uri"))
	}

	// Validate response type
	if responseType != "code" {
		return c.JSON(http.StatusBadRequest, errors.NewInvalidRequest("Unsupported response_type"))
	}

	// Validate scope
	if err := api.clientService.ValidateScope(c.Request().Context(), clientID, strings.Split(scope, " ")); err != nil {
		return c.JSON(http.StatusBadRequest, errors.NewInvalidScope("Invalid scope requested"))
	}

	// Check if PKCE is required
	requiresPKCE, _ := api.clientService.RequiresPKCE(c.Request().Context(), clientID)
	if requiresPKCE {
		codeChallenge := c.QueryParam("code_challenge")
		codeChallengeMethod := c.QueryParam("code_challenge_method")
		if codeChallenge == "" {
			return c.JSON(http.StatusBadRequest, errors.NewPKCERequired())
		}
		if codeChallengeMethod != "S256" && codeChallengeMethod != "plain" {
			return c.JSON(http.StatusBadRequest, errors.NewInvalidRequest("Invalid code_challenge_method"))
		}
	}

	// Generate authorization code
	authCode, err := api.service.GenerateAuthCode(c.Request().Context(), clientID, redirectURI, scope)
	if err != nil {
		log.Error().Err(err).Msg("Failed to generate authorization code")
		return c.JSON(http.StatusInternalServerError, errors.NewServerError("Failed to generate authorization code"))
	}

	// Build redirect URL
	redirectURL := fmt.Sprintf("%s?code=%s", redirectURI, authCode)
	if state != "" {
		redirectURL += "&state=" + state
	}

	return c.Redirect(http.StatusFound, redirectURL)
}

// TokenHandler handles OAuth2 token requests. It:
//   - Extracts client_id, client_secret, and grant_type from the request form values.
//   - Validates the client credentials and grant type.
//   - Processes the grant type by calling one of three handler functions based on the
//     grant type (authorization_code, refresh_token, or client_credentials).
//   - Returns a JSON response with the token response if successful, or an error response
//     if any of the validation or processing steps fail.
func (api *OAuth2API) TokenHandler(c echo.Context) error {
	clientID := c.FormValue("client_id")
	clientSecret := c.FormValue("client_secret")
	grantType := c.FormValue("grant_type")

	ctx := c.Request().Context()

	// Validate cli
	cli, err := api.clientService.ValidateClient(ctx, clientID, clientSecret)
	if err != nil {
		return c.JSON(http.StatusUnauthorized, errors.NewInvalidClient("Invalid client credentials"))
	}

	// Validate grant type
	if err := api.clientService.ValidateGrantType(ctx, clientID, grantType); err != nil {
		return c.JSON(http.StatusBadRequest, errors.NewUnauthorizedClient("Grant type not allowed for this client"))
	}

	// Process grant type
	var tokenResponse *TokenResponse
	var processErr error

	switch grantType {
	case "authorization_code":
		tokenResponse, processErr = api.handleAuthorizationCodeGrant(c, cli)
	case "refresh_token":
		tokenResponse, processErr = api.handleRefreshTokenGrant(c, cli)
	case "client_credentials":
		tokenResponse, processErr = api.handleClientCredentialsGrant(c, cli)
	case "password":
		tokenResponse, processErr = api.handlePasswordGrant(c, cli)
	default:
		return c.JSON(http.StatusBadRequest, errors.NewUnsupportedGrantType())
	}

	if processErr != nil {
		if oauthErr, ok := processErr.(*errors.OAuth2Error); ok {
			return c.JSON(http.StatusBadRequest, oauthErr)
		}
		log.Error().Err(processErr).Msg("Token generation failed")
		return c.JSON(http.StatusInternalServerError, errors.NewServerError("Failed to generate token"))
	}

	return c.JSON(http.StatusOK, tokenResponse)
}

// UserInfoHandler handles HTTP requests to retrieve user information. It expects an "Authorization"
// header with a Bearer token, validates the token, and returns the associated user information if
// valid. If the token is missing, invalid, or cannot be validated, it returns a JSON error response
// with a 401 Unauthorized status code.
func (api *OAuth2API) UserInfoHandler(c echo.Context) error {
	authHeader := c.Request().Header.Get("Authorization")
	if authHeader == "" {
		return c.JSON(http.StatusUnauthorized, echo.Map{"error": "missing_token"})
	}

	ctx := c.Request().Context()

	// Get bearer token
	tokenParts := strings.Split(authHeader, " ")
	if len(tokenParts) != 2 || tokenParts[0] != "Bearer" {
		return c.JSON(http.StatusUnauthorized, echo.Map{"error": "invalid_token"})
	}
	token := tokenParts[1]

	// Validate token, and get user info
	userInfo, err := api.service.GetUserInfo(ctx, token)
	if err != nil {
		return c.JSON(http.StatusUnauthorized, echo.Map{"error": "invalid_token"})
	}

	return c.JSON(http.StatusOK, userInfo)
}

// RevokeHandler handles token revocation requests according to RFC 7009.
// It accepts both access tokens and refresh tokens and revokes them.
// The endpoint always returns 200 OK regardless of whether the token was
// successfully revoked or not.
func (api *OAuth2API) RevokeHandler(c echo.Context) error {
	token := c.FormValue("token")
	if token == "" {
		return c.JSON(http.StatusBadRequest, echo.Map{
			"error":             "invalid_request",
			"error_description": "token parameter is required",
		})
	}

	tokenType := c.FormValue("token_type_hint")
	if tokenType == "" {
		tokenType = "access_token"
	}

	// Validate token type hint
	if tokenType != "access_token" && tokenType != "refresh_token" {
		tokenType = "access_token" // Default to access_token if invalid hint
	}

	ctx := c.Request().Context()

	if err := api.service.RevokeToken(ctx, token); err != nil {
		// According to RFC 7009 section 2.2, the authorization server SHOULD
		// respond with HTTP status code 200 even when the token was invalid
		log.Error().
			Err(err).
			Str("token_type", tokenType).
			Msg("Failed to revoke token")
	}

	return c.JSON(http.StatusOK, echo.Map{})
}

// AuthorizeRequest represents an OAuth 2.0 authorization request
type AuthorizeRequest struct {
	ClientID     string
	RedirectURI  string
	ResponseType string
	Scope        string
	State        string
}

// TokenRequest represents an OAuth 2.0 token request
type TokenRequest struct {
	GrantType    string
	Code         string
	RedirectURI  string
	ClientID     string
	ClientSecret string
	RefreshToken string
}

// TokenResponse represents an OAuth 2.0 token response
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

// OpenIDConfiguration represents the OpenID Connect discovery document
//
//nolint:tagliatelle
type OpenIDConfiguration struct {
	Issuer                                    string   `json:"issuer"`
	AuthorizationEndpoint                     string   `json:"authorization_endpoint"`
	TokenEndpoint                             string   `json:"token_endpoint"`
	UserInfoEndpoint                          string   `json:"userinfo_endpoint"`
	JwksURI                                   string   `json:"jwks_uri"`
	RegistrationEndpoint                      *string  `json:"registration_endpoint,omitempty"`
	ScopesSupported                           []string `json:"scopes_supported"`
	ResponseTypesSupported                    []string `json:"response_types_supported"`
	ResponseModesSupported                    []string `json:"response_modes_supported"`
	GrantTypesSupported                       []string `json:"grant_types_supported"`
	TokenEndpointAuthMethodsSupported         []string `json:"token_endpoint_auth_methods_supported"`
	TokenEndpointAuthSigningAlgSupported      []string `json:"token_endpoint_auth_signing_alg_values_supported,omitempty"`
	ServiceDocumentation                      *string  `json:"service_documentation,omitempty"`
	UILocalesSupported                        []string `json:"ui_locales_supported,omitempty"`
	OpPolicyURI                               *string  `json:"op_policy_uri,omitempty"`
	OpTosURI                                  *string  `json:"op_tos_uri,omitempty"`
	RevocationEndpoint                        *string  `json:"revocation_endpoint,omitempty"`
	RevocationEndpointAuthMethodsSupported    []string `json:"revocation_endpoint_auth_methods_supported,omitempty"`
	IntrospectionEndpoint                     *string  `json:"introspection_endpoint,omitempty"`
	IntrospectionEndpointAuthMethodsSupported []string `json:"introspection_endpoint_auth_methods_supported,omitempty"`
	CodeChallengeMethodsSupported             []string `json:"code_challenge_methods_supported,omitempty"`
	SubjectTypesSupported                     []string `json:"subject_types_supported"`
	IDTokenSigningAlgValuesSupported          []string `json:"id_token_signing_alg_values_supported"`
	IDTokenEncryptionAlgValuesSupported       []string `json:"id_token_encryption_alg_values_supported,omitempty"`
	IDTokenEncryptionEncValuesSupported       []string `json:"id_token_encryption_enc_values_supported,omitempty"`
	UserinfoSigningAlgValuesSupported         []string `json:"userinfo_signing_alg_values_supported,omitempty"`
	UserinfoEncryptionAlgValuesSupported      []string `json:"userinfo_encryption_alg_values_supported,omitempty"`
	UserinfoEncryptionEncValuesSupported      []string `json:"userinfo_encryption_enc_values_supported,omitempty"`
	RequestObjectSigningAlgValuesSupported    []string `json:"request_object_signing_alg_values_supported,omitempty"`
	RequestObjectEncryptionAlgValuesSupported []string `json:"request_object_encryption_alg_values_supported,omitempty"`
	RequestObjectEncryptionEncValuesSupported []string `json:"request_object_encryption_enc_values_supported,omitempty"`
	ClaimsSupported                           []string `json:"claims_supported,omitempty"`
	ClaimsParameterSupported                  bool     `json:"claims_parameter_supported"`
	RequestParameterSupported                 bool     `json:"request_parameter_supported"`
	RequestURIParameterSupported              bool     `json:"request_uri_parameter_supported"`
	RequireRequestURIRegistration             bool     `json:"require_request_uri_registration"`
}

func (api *OAuth2API) OpenIDConfigurationHandler(c echo.Context) error {
	baseURL := c.Scheme() + "://" + c.Request().Host

	config := OpenIDConfiguration{
		Issuer:                baseURL,
		AuthorizationEndpoint: baseURL + "/oauth2/authorize",
		TokenEndpoint:         baseURL + "/oauth2/token",
		UserInfoEndpoint:      baseURL + "/oauth2/userinfo",
		JwksURI:               baseURL + "/.well-known/jwks.json",
		RevocationEndpoint:    stringPtr(baseURL + "/oauth2/revoke"),
		IntrospectionEndpoint: stringPtr(baseURL + "/oauth2/introspect"),
		ScopesSupported:       []string{"openid", "profile", "email", "offline_access"},
		ResponseTypesSupported: []string{
			"code", "token", "id_token", "code token", "code id_token", "token id_token", "code token id_token",
		},
		ResponseModesSupported:            []string{"query", "fragment", "form_post"},
		GrantTypesSupported:               []string{"authorization_code", "implicit", "refresh_token", "client_credentials"},
		TokenEndpointAuthMethodsSupported: []string{"client_secret_basic", "client_secret_post", "private_key_jwt"},
		SubjectTypesSupported:             []string{"public", "pairwise"},
		IDTokenSigningAlgValuesSupported:  []string{"RS256", "RS384", "RS512"},
		UserinfoSigningAlgValuesSupported: []string{"RS256", "RS384", "RS512"},
		CodeChallengeMethodsSupported:     []string{"plain", "S256"},
		ClaimsSupported:                   []string{"sub", "iss", "auth_time", "name", "given_name", "family_name", "email"},
		ClaimsParameterSupported:          true,
		RequestParameterSupported:         true,
		RequestURIParameterSupported:      true,
		RequireRequestURIRegistration:     true,
	}

	return c.JSON(http.StatusOK, config)
}

// Helper function to convert string to pointer
func stringPtr(s string) *string {
	return &s
}

// DirectGrantHandler handles the Resource Owner Password Credentials flow
func (api *OAuth2API) DirectGrantHandler(c echo.Context) error {
	clientID := c.FormValue("client_id")
	clientSecret := c.FormValue("client_secret")
	username := c.FormValue("username")
	password := c.FormValue("password")
	scope := c.FormValue("scope")

	if clientID == "" || clientSecret == "" || username == "" || password == "" {
		return c.JSON(http.StatusBadRequest, echo.Map{
			"error":             "invalid_request",
			"error_description": "Missing required parameters",
		})
	}

	ctx := c.Request().Context()

	token, err := api.service.DirectGrant(ctx, clientID, clientSecret, username, password, scope)
	if err != nil {
		log.Error().Err(err).Msg("direct grant failed")
		return c.JSON(http.StatusBadRequest, echo.Map{
			"error":             "invalid_grant",
			"error_description": "Invalid credentials",
		})
	}

	return c.JSON(http.StatusOK, token)
}

// ClientCredentialsHandler handles the Client Credentials flow
func (api *OAuth2API) ClientCredentialsHandler(c echo.Context) error {
	clientID := c.FormValue("client_id")
	clientSecret := c.FormValue("client_secret")
	scope := c.FormValue("scope")

	if clientID == "" || clientSecret == "" {
		return c.JSON(http.StatusBadRequest, echo.Map{
			"error":             "invalid_request",
			"error_description": "Missing client credentials",
		})
	}

	ctx := c.Request().Context()

	token, err := api.service.ClientCredentials(ctx, clientID, clientSecret, scope)
	if err != nil {
		log.Error().Err(err).Msg("client credentials grant failed")
		return c.JSON(http.StatusBadRequest, echo.Map{
			"error":             "invalid_client",
			"error_description": "Invalid client credentials",
		})
	}

	return c.JSON(http.StatusOK, token)
}

func (api *OAuth2API) handleAuthorizationCodeGrant(c echo.Context, cli *client.Client) (*TokenResponse, error) {
	code := c.FormValue("code")
	redirectURI := c.FormValue("redirect_uri")
	codeVerifier := c.FormValue("code_verifier")

	ctx := c.Request().Context()

	// Validate PKCE if required
	requiresPKCE, _ := api.clientService.RequiresPKCE(ctx, cli.ID)
	if requiresPKCE {
		if codeVerifier == "" {
			return nil, errors.NewPKCERequired()
		}
		if err := api.pkceService.ValidateCodeVerifier(ctx, code, codeVerifier); err != nil {
			return nil, errors.NewInvalidPKCE(err.Error())
		}
	}

	return api.service.ExchangeAuthorizationCode(ctx, code, cli.ID, cli.Secret, redirectURI)
}

func (api *OAuth2API) handlePasswordGrant(c echo.Context, cli *client.Client) (*TokenResponse, error) {
	username := c.FormValue("username")
	password := c.FormValue("password")
	clientID := c.FormValue("client_id")
	clientSecret := c.FormValue("client_secret")
	scope := c.FormValue("scope")

	if username == "" || password == "" || clientID == "" || clientSecret == "" {
		return nil, errors.NewInvalidRequest("missing required parameters. " +
			"Required parameters: username, password, client_id, client_secret")
	}

	ctx := c.Request().Context()

	return api.service.PasswordGrant(ctx, username, password, scope, cli)
}

func (api *OAuth2API) handleClientCredentialsGrant(c echo.Context, cli *client.Client) (*TokenResponse, error) {
	scope := c.FormValue("scope")

	ctx := c.Request().Context()

	return api.service.ClientCredentialsGrant(ctx, cli.ID, cli.Secret, scope)
}

func (api *OAuth2API) handleRefreshTokenGrant(c echo.Context, cli *client.Client) (*TokenResponse, error) {
	refreshToken := c.FormValue("refresh_token")
	if refreshToken == "" {
		return nil, errors.NewInvalidRequest("refresh_token is required")
	}

	ctx := c.Request().Context()

	return api.service.RefreshToken(ctx, refreshToken, cli.ID)
}

// IntrospectHandler implements RFC 7662 Token Introspection. It checks for required parameters
// (client_id, client_secret, and token), authenticates the client, and then calls the
// IntrospectToken method to inspect the token. If the introspection fails, it returns
// a 200 OK response with active=false as per the RFC. Otherwise, it returns the introspection result.
func (api *OAuth2API) IntrospectHandler(c echo.Context) error {
	// Token introspection requires authentication
	clientID := c.FormValue("client_id")
	clientSecret := c.FormValue("client_secret")

	if clientID == "" || clientSecret == "" {
		return c.JSON(http.StatusUnauthorized, echo.Map{
			"error": "invalid_client",
		})
	}

	token := c.FormValue("token")
	if token == "" {
		return c.JSON(http.StatusBadRequest, echo.Map{
			"error":             "invalid_request",
			"error_description": "token parameter is required",
		})
	}

	tokenType := c.FormValue("token_type_hint")

	ctx := c.Request().Context()

	introspection, err := api.service.IntrospectToken(ctx, token, tokenType, clientID, clientSecret)
	if err != nil {
		log.Error().Err(err).Msg("token introspection failed")
		// According to RFC 7662, we should still return 200 OK with active=false
		return c.JSON(http.StatusOK, echo.Map{
			"active": false,
		})
	}

	return c.JSON(http.StatusOK, introspection)
}
