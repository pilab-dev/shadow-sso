//go:build gin

//nolint:varnamelen,tagliatelle
package sssogin

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	ssso "github.com/pilab-dev/shadow-sso"
	sssoapi "github.com/pilab-dev/shadow-sso/api"
	"github.com/pilab-dev/shadow-sso/client"
	"github.com/pilab-dev/shadow-sso/errors"
	"github.com/rs/zerolog/log"
)

// OAuth2API struct to hold dependencies.
type OAuth2API struct {
	service       *ssso.OAuthService
	jwksService   *ssso.JWKSService
	clientService *client.ClientService
	pkceService   *ssso.PKCEService
	config        *ssso.OpenIDProviderConfig
}

// NewOAuth2API initializes the OAuth2 API.
func NewOAuth2API(
	service *ssso.OAuthService,
	jwksService *ssso.JWKSService,
	clientService *client.ClientService,
	pkceService *ssso.PKCEService,
	config *ssso.OpenIDProviderConfig,
) *OAuth2API {
	if config == nil {
		config = ssso.NewDefaultConfig("https://sso.pilab.hu")
	}
	return &OAuth2API{
		service:       service,
		jwksService:   jwksService,
		clientService: clientService,
		pkceService:   pkceService,
		config:        config,
	}
}

// RegisterRoutes registers the OAuth2 routes.
func (oa *OAuth2API) RegisterRoutes(e *gin.Engine) {
	e.POST("/oauth2/token", oa.TokenHandler)
	e.GET("/oauth2/authorize", oa.AuthorizeHandler)
	e.GET("/oauth2/userinfo", oa.UserInfoHandler)
	e.POST("/oauth2/revoke", oa.RevokeHandler)
	e.POST("/oauth2/introspect", oa.IntrospectHandler)

	// OpenID Configuration endpoints
	e.GET("/.well-known/openid-configuration", oa.OpenIDConfigurationHandler)
	e.GET("/.well-known/jwks.json", oa.JWKSHandler)
}

// AuthorizeHandler handles OAuth 2.0 authorization requests. It validates the client, redirect URI,
// response type, scope, and PKCE (Proof Key for Code Exchange) requirements. If all validations pass,
// it generates an authorization code and redirects the user to the provided redirect URI with the code.
//
//nolint:funlen
func (oa *OAuth2API) AuthorizeHandler(c *gin.Context) {
	clientID := c.Query("client_id")
	redirectURI := c.Query("redirect_uri")
	responseType := c.Query("response_type")
	scope := c.Query("scope")
	state := c.Query("state")

	ctx := c.Request.Context()

	// Validate client
	_, err := oa.clientService.GetClient(ctx, clientID)
	if err != nil {
		c.JSON(http.StatusBadRequest, errors.NewInvalidClient("Invalid client_id"))
		return
	}

	// Validate redirect URI
	if err := oa.clientService.ValidateRedirectURI(ctx, clientID, redirectURI); err != nil {
		c.JSON(http.StatusBadRequest, errors.NewInvalidRequest("Invalid redirect_uri"))
		return
	}

	// Validate response type
	if responseType != "code" {
		c.JSON(http.StatusBadRequest, errors.NewInvalidRequest("Unsupported response_type"))
		return
	}

	// Validate scope
	if err := oa.clientService.ValidateScope(ctx, clientID, strings.Split(scope, " ")); err != nil {
		c.JSON(http.StatusBadRequest, errors.NewInvalidScope("Invalid scope requested"))
		return
	}

	// Check if PKCE is required
	requiresPKCE, _ := oa.clientService.RequiresPKCE(ctx, clientID)
	if requiresPKCE {
		codeChallenge := c.Query("code_challenge")
		codeChallengeMethod := c.Query("code_challenge_method")
		if codeChallenge == "" {
			c.JSON(http.StatusBadRequest, errors.NewPKCERequired())
			return
		}
		if codeChallengeMethod != "S256" && codeChallengeMethod != "plain" {
			c.JSON(http.StatusBadRequest, errors.NewInvalidRequest("Invalid code_challenge_method"))
			return
		}
	}

	// Generate authorization code
	authCode, err := oa.service.GenerateAuthCode(ctx, clientID, redirectURI, scope)
	if err != nil {
		log.Error().Err(err).Msg("Failed to generate authorization code")
		c.JSON(http.StatusInternalServerError, errors.NewServerError("Failed to generate authorization code"))
		return
	}

	// Build redirect URL
	redirectURL := fmt.Sprintf("%s?code=%s", redirectURI, authCode)
	if state != "" {
		redirectURL += "&state=" + state
	}

	c.Redirect(http.StatusFound, redirectURL)
}

// GrantType enumeration for OAuth2 grant types.
type GrantType string

const (
	GrantTypeAuthorizationCode GrantType = "authorization_code"
	GrantTypeRefreshToken      GrantType = "refresh_token"
	GrantTypeClientCredentials GrantType = "client_credentials"
	GrantTypePassword          GrantType = "password"
)

// TokenHandler handles OAuth2 token requests. It:
//   - Extracts client_id, client_secret, and grant_type from the request form values.
//   - Validates the client credentials and grant type.
//   - Processes the grant type by calling one of three handler functions based on the
//     grant type (authorization_code, refresh_token, or client_credentials).
//   - Returns a JSON response with the token response if successful, or an error response
//     if any of the validation or processing steps fail.
//
//nolint:funlen
func (oa *OAuth2API) TokenHandler(c *gin.Context) {
	clientID := c.PostForm("client_id")
	clientSecret := c.PostForm("client_secret")
	grantType := c.PostForm("grant_type")

	ctx := c.Request.Context()

	// Validate cli
	cli, err := oa.clientService.ValidateClient(ctx, clientID, clientSecret)
	if err != nil {
		log.Error().Err(err).Msg("Invalid client credentials")

		c.JSON(http.StatusUnauthorized, errors.NewInvalidClient("Invalid client credentials"))
		return
	}

	// Validate grant type
	if err := oa.clientService.ValidateGrantType(ctx, clientID, grantType); err != nil {
		log.Error().Err(err).Msg("Grant type not allowed for this client")

		c.JSON(http.StatusBadRequest, errors.NewUnauthorizedClient("Grant type not allowed for this client"))
		return
	}

	// Process grant type
	var tokenResponse *sssoapi.TokenResponse
	var processErr error

	switch GrantType(grantType) {
	case GrantTypeAuthorizationCode:
		tokenResponse, processErr = oa.handleAuthorizationCodeGrant(c, cli)
	case GrantTypeRefreshToken:
		tokenResponse, processErr = oa.handleRefreshTokenGrant(c, cli)
	case GrantTypeClientCredentials:
		tokenResponse, processErr = oa.handleClientCredentialsGrant(c, cli)
	case GrantTypePassword: // ! This method is not supported by the OAuth2 2.1 spec
		tokenResponse, processErr = oa.handlePasswordGrant(c, cli)
	default:
		c.JSON(http.StatusBadRequest, errors.NewUnsupportedGrantType())
		return
	}

	if processErr != nil {
		if oauthErr, ok := processErr.(*errors.OAuth2Error); ok {
			log.Error().Err(oauthErr).Msg("Token generation failed")

			c.JSON(http.StatusBadRequest, oauthErr)

			return
		}

		log.Error().Err(processErr).Msg("Token generation failed")

		c.JSON(http.StatusInternalServerError, errors.NewServerError("Failed to generate token"))

		return
	}

	log.Info().
		Str("client_id", clientID).
		Str("grant_type", grantType).
		Int("expires_in", tokenResponse.ExpiresIn).
		Str("token_type", tokenResponse.TokenType).
		Str("access_token", tokenResponse.AccessToken).
		Str("refresh_token", tokenResponse.RefreshToken).
		Str("id_token", tokenResponse.IDToken).
		Msg("Token generated")

	// Return token
	c.JSON(http.StatusOK, tokenResponse)
}

// UserInfoHandler handles HTTP requests to retrieve user information. It expects an "Authorization"
// header with a Bearer token, validates the token, and returns the associated user information if
// valid. If the token is missing, invalid, or cannot be validated, it returns a JSON error response
// with a 401 Unauthorized status code.
func (oa *OAuth2API) UserInfoHandler(c *gin.Context) {
	authHeader := c.Request.Header.Get("Authorization")
	if authHeader == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "missing_token"})
		return
	}

	ctx := c.Request.Context()

	// Get bearer token
	tokenParts := strings.Split(authHeader, " ")
	if len(tokenParts) != 2 || tokenParts[0] != "Bearer" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_token"})
		return
	}
	token := tokenParts[1]

	// Validate token, and get user info
	userInfo, err := oa.service.GetUserInfo(ctx, token)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_token"})
		return
	}

	c.JSON(http.StatusOK, userInfo)
}

// RevokeHandler handles token revocation requests according to RFC 7009.
// It accepts both access tokens and refresh tokens and revokes them.
// Client authentication is required.
// The endpoint returns 200 OK if the request was processed, regardless of
// whether the token was found or valid, as per RFC 7009.
// Errors related to client authentication or invalid requests will result in
// appropriate HTTP error responses.
func (oa *OAuth2API) RevokeHandler(c *gin.Context) {
	token := c.PostForm("token")
	if token == "" {
		c.JSON(http.StatusBadRequest, errors.NewInvalidRequest("token parameter is required"))
		return
	}

	tokenTypeHint := c.PostForm("token_type_hint")
	// Optional: Validate token_type_hint if specific values are enforced.
	// For now, we pass it along. If empty, service might default or try to infer.

	clientID := c.PostForm("client_id")
	clientSecret := c.PostForm("client_secret")

	if clientID == "" {
		// Client authentication can also be done via Basic Auth header,
		// but RFC 7009 suggests POST body params for client_id for public clients.
		// For confidential clients, Authorization header is also common.
		// Here, we are strictly checking POST body for client_id and client_secret.
		c.JSON(http.StatusBadRequest, errors.NewInvalidRequest("client_id parameter is required"))
		return
	}
	// Note: client_secret might be optional for public clients.
	// The service.RevokeToken will ultimately decide based on client's configuration.

	ctx := c.Request.Context()

	err := oa.service.RevokeToken(ctx, token, tokenTypeHint, clientID, clientSecret)
	if err != nil {
		// Check for specific OAuth errors to return appropriate status codes
		if oerr, ok := err.(*errors.OAuth2Error); ok {
			if oerr.Err == errors.ErrInvalidClientCredentials.Err || oerr.Err == errors.ErrInvalidClient.Err {
				log.Warn().Err(err).Str("client_id", clientID).Msg("Client authentication failed during token revocation")
				c.JSON(http.StatusUnauthorized, oerr)
				return
			}
			// For other OAuth2 specific errors that are client's fault
			log.Warn().Err(err).Str("client_id", clientID).Str("token_type_hint", tokenTypeHint).Msg("OAuth error during token revocation")
			c.JSON(http.StatusBadRequest, oerr)
			return
		}

		// Log internal server errors
		log.Error().
			Err(err).
			Str("client_id", clientID).
			Str("token_type_hint", tokenTypeHint).
			Msg("Internal server error during token revocation")
		// Even for internal errors, RFC 7009 is a bit ambiguous.
		// It says "the server responds with HTTP status code 200 OK to indicate that it has processed the request".
		// However, an internal server error means the request might not have been fully processed as intended.
		// For now, adhering strictly to "always 200 OK" for any error post client auth might be too broad.
		// Let's assume client auth errors are separate and lead to 400/401.
		// If RevokeToken itself has an internal issue *after* client auth,
		// we might still return 200, or choose 500 for operational insight.
		// The previous implementation of OAuthService.RevokeToken now always returns nil,
		// so this specific path for internal errors from RevokeToken (post-client-auth) is less likely.
		// The error here would most likely be from `validateClient` within `RevokeToken`.
		// If `validateClient` fails, `RevokeToken` returns that error.
		c.JSON(http.StatusInternalServerError, errors.NewServerError("Internal server error"))
		return
	}

	// As per RFC 7009, if the client authentication was successful,
	// the server MUST respond with HTTP 200 OK status code, regardless of whether
	// the token was found or is invalid.
	c.Status(http.StatusOK)
}

// AuthorizeRequest represents an OAuth 2.0 authorization request.
type AuthorizeRequest struct {
	ClientID     string
	RedirectURI  string
	ResponseType string
	Scope        string
	State        string
}

// TokenRequest represents an OAuth 2.0 token request.
type TokenRequest struct {
	GrantType    string
	Code         string
	RedirectURI  string
	ClientID     string
	ClientSecret string
	RefreshToken string
}

func (oa *OAuth2API) OpenIDConfigurationHandler(c *gin.Context) {
	baseURL := c.Request.URL.Scheme + "://" + c.Request.Host
	cfg := oa.config // Use the injected OpenIDProviderConfig

	// Initialize the response struct
	resp := sssoapi.OpenIDConfiguration{}

	// 1. Issuer
	if cfg.Issuer != "" {
		resp.Issuer = cfg.Issuer
	} else {
		resp.Issuer = baseURL // Fallback to baseURL if config issuer is empty
	}

	// 2. Standard Endpoints
	if cfg.EnabledEndpoints.Authorization {
		resp.AuthorizationEndpoint = baseURL + "/oauth2/authorize"
	}
	if cfg.EnabledEndpoints.Token {
		resp.TokenEndpoint = baseURL + "/oauth2/token"
	}
	if cfg.EnabledEndpoints.UserInfo {
		resp.UserInfoEndpoint = baseURL + "/oauth2/userinfo"
	}
	if cfg.EnabledEndpoints.JWKS {
		resp.JwksURI = baseURL + "/.well-known/jwks.json"
	}

	// 3. Conditional Endpoints
	if cfg.EnabledEndpoints.Revocation {
		resp.RevocationEndpoint = ToPtr(baseURL + "/oauth2/revoke")
	}
	if cfg.EnabledEndpoints.Introspection {
		resp.IntrospectionEndpoint = ToPtr(baseURL + "/oauth2/introspect")
	}
	if cfg.EnabledEndpoints.EndSession {
		resp.EndSessionEndpoint = ToPtr(baseURL + "/oauth2/logout") // Assuming /oauth2/logout
	}
	if cfg.EnabledEndpoints.Registration {
		resp.RegistrationEndpoint = ToPtr(baseURL + "/oauth2/register") // Assuming /oauth2/register
	}

	// 4. Supported Grant Types
	grantTypesSupported := []string{}
	if cfg.EnabledGrantTypes.AuthorizationCode {
		grantTypesSupported = append(grantTypesSupported, "authorization_code")
	}
	if cfg.EnabledGrantTypes.ClientCredentials {
		grantTypesSupported = append(grantTypesSupported, "client_credentials")
	}
	if cfg.EnabledGrantTypes.RefreshToken {
		grantTypesSupported = append(grantTypesSupported, "refresh_token")
	}
	if cfg.EnabledGrantTypes.Password {
		grantTypesSupported = append(grantTypesSupported, "password")
	}
	if cfg.EnabledGrantTypes.Implicit {
		// "implicit" is not a grant type for the token endpoint but often listed.
		// It enables flows that result in tokens being issued directly from the authorization endpoint.
		grantTypesSupported = append(grantTypesSupported, "implicit")
	}
	if cfg.EnabledGrantTypes.JWTBearer {
		grantTypesSupported = append(grantTypesSupported, "urn:ietf:params:oauth:grant-type:jwt-bearer")
	}
	if cfg.EnabledGrantTypes.DeviceCode {
		grantTypesSupported = append(grantTypesSupported, "urn:ietf:params:oauth:grant-type:device_code")
	}
	if len(grantTypesSupported) > 0 {
		resp.GrantTypesSupported = grantTypesSupported
	} else {
		resp.GrantTypesSupported = []string{} // Ensure empty array if none are supported
	}

	// 5. Supported Response Types
	if len(cfg.TokenConfig.SupportedResponseTypes) > 0 {
		resp.ResponseTypesSupported = cfg.TokenConfig.SupportedResponseTypes
	} else {
		resp.ResponseTypesSupported = []string{}
	}

	// 6. Supported Response Modes
	if len(cfg.TokenConfig.SupportedResponseModes) > 0 {
		resp.ResponseModesSupported = cfg.TokenConfig.SupportedResponseModes
	} else {
		// Default if not specified, as per previous hardcoding
		resp.ResponseModesSupported = []string{"query", "fragment", "form_post"}
	}

	// 7. Supported Scopes
	if len(cfg.ClaimsConfig.SupportedScopes) > 0 {
		resp.ScopesSupported = cfg.ClaimsConfig.SupportedScopes
	} else {
		resp.ScopesSupported = []string{}
	}

	// 8. Supported Subject Types (Defaulting as per previous hardcoding if no specific config field)
	// Assuming no direct field in cfg. For now, keep previous default.
	// If a field like cfg.SubjectTypesSupported exists, it should be used.
	resp.SubjectTypesSupported = []string{"public", "pairwise"} // Default or from cfg if available

	// 9. Supported Token Endpoint Auth Methods
	if len(cfg.TokenConfig.SupportedTokenEndpointAuth) > 0 {
		resp.TokenEndpointAuthMethodsSupported = cfg.TokenConfig.SupportedTokenEndpointAuth
	} else {
		resp.TokenEndpointAuthMethodsSupported = []string{}
	}

	// 10. Supported Signing Algorithms
	// Assuming SecurityConfig.AllowedSigningAlgs is the source for these
	if len(cfg.SecurityConfig.AllowedSigningAlgs) > 0 {
		resp.IDTokenSigningAlgValuesSupported = cfg.SecurityConfig.AllowedSigningAlgs
		resp.UserinfoSigningAlgValuesSupported = cfg.SecurityConfig.AllowedSigningAlgs      // Or a more specific field if exists
		resp.RequestObjectSigningAlgValuesSupported = cfg.SecurityConfig.AllowedSigningAlgs // Or a more specific field
	} else {
		resp.IDTokenSigningAlgValuesSupported = []string{}
		resp.UserinfoSigningAlgValuesSupported = []string{}
		resp.RequestObjectSigningAlgValuesSupported = []string{}
	}
	// Encryption related algs (id_token_encryption_alg_values_supported, etc.)
	// would follow a similar pattern if configured in SecurityConfig.AllowedEncryptionAlgs/Enc

	// 11. Supported Claims
	if len(cfg.ClaimsConfig.SupportedClaims) > 0 {
		resp.ClaimsSupported = cfg.ClaimsConfig.SupportedClaims
	} else {
		resp.ClaimsSupported = []string{}
	}

	// 12. PKCE Support
	if cfg.PKCEConfig.Enabled && len(cfg.PKCEConfig.SupportedMethods) > 0 {
		resp.CodeChallengeMethodsSupported = cfg.PKCEConfig.SupportedMethods
	} else {
		// If PKCE is disabled, or no methods specified, omit or provide empty array
		resp.CodeChallengeMethodsSupported = []string{}
	}

	// 13. Other Boolean Flags
	resp.ClaimsParameterSupported = cfg.ClaimsConfig.EnableClaimsParameter
	// For RequestParameterSupported & RequestURIParameterSupported, using true as per previous hardcoding
	// if no direct config field. Assume these are generally supported.
	resp.RequestParameterSupported = true  // Default or from cfg if available
	resp.RequestURIParameterSupported = true // Default or from cfg if available
	resp.RequireRequestURIRegistration = cfg.SecurityConfig.RequireRequestURIRegistration

	// Other fields from sssoapi.OpenIDConfiguration that might need mapping or defaults:
	// TokenEndpointAuthSigningAlgSupported, ServiceDocumentation, UILocalesSupported,
	// OpPolicyURI, OpTosURI, RevocationEndpointAuthMethodsSupported,
	// IntrospectionEndpointAuthMethodsSupported, IDTokenEncryptionAlgValuesSupported,
	// IDTokenEncryptionEncValuesSupported, UserinfoEncryptionAlgValuesSupported,
	// UserinfoEncryptionEncValuesSupported, RequestObjectEncryptionAlgValuesSupported,
	// RequestObjectEncryptionEncValuesSupported.
	// These are omitted if not directly available in oa.config or not specified in the task.
	// For example, if token endpoint supports JWT auth, TokenEndpointAuthSigningAlgSupported would list algs.
	// For now, focusing on explicitly mentioned fields.

	c.JSON(http.StatusOK, resp)
}

// ToPtr returns a pointer to the given value. Its a helper function to provide a more readable code
// Example:
//
//	    // Using this method the "/register" will be a pointer (*string)
//		oidc.RegistrationEndpoint := ToPtr("/register")
func ToPtr[T any](s T) *T {
	return &s
}

// DirectGrantHandler handles the Resource Owner Password Credentials flow
func (oa *OAuth2API) DirectGrantHandler(c *gin.Context) {
	clientID := c.PostForm("client_id")
	clientSecret := c.PostForm("client_secret")
	username := c.PostForm("username")
	password := c.PostForm("password")
	scope := c.PostForm("scope")

	if clientID == "" || clientSecret == "" || username == "" || password == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": "Missing required parameters",
		})
		return
	}

	ctx := c.Request.Context()

	token, err := oa.service.DirectGrant(ctx, clientID, clientSecret, username, password, scope)
	if err != nil {
		log.Error().Err(err).Msg("direct grant failed")
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_grant",
			"error_description": "Invalid credentials",
		})
		return
	}

	c.JSON(http.StatusOK, token)
}

// ClientCredentialsHandler handles the Client Credentials flow
func (oa *OAuth2API) ClientCredentialsHandler(c *gin.Context) {
	clientID := c.PostForm("client_id")
	clientSecret := c.PostForm("client_secret")
	scope := c.PostForm("scope")

	if clientID == "" || clientSecret == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": "Missing client credentials",
		})
		return
	}

	ctx := c.Request.Context()

	token, err := oa.service.ClientCredentials(ctx, clientID, clientSecret, scope)
	if err != nil {
		log.Error().Err(err).Msg("client credentials grant failed")
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_client",
			"error_description": "Invalid client credentials",
		})
		return
	}

	c.JSON(http.StatusOK, token)
}

func (oa *OAuth2API) handleAuthorizationCodeGrant(c *gin.Context, cli *client.Client) (*sssoapi.TokenResponse, error) {
	code := c.PostForm("code")
	redirectURI := c.PostForm("redirect_uri")
	codeVerifier := c.PostForm("code_verifier")

	ctx := c.Request.Context()

	// Validate PKCE if required
	requiresPKCE, _ := oa.clientService.RequiresPKCE(ctx, cli.ID)
	if requiresPKCE {
		if codeVerifier == "" {
			return nil, errors.NewPKCERequired()
		}
		if err := oa.pkceService.ValidateCodeVerifier(ctx, code, codeVerifier); err != nil {
			return nil, errors.NewInvalidPKCE(err.Error())
		}
	}

	return oa.service.ExchangeAuthorizationCode(ctx, code, cli.ID, cli.Secret, redirectURI)
}

func (oa *OAuth2API) handlePasswordGrant(c *gin.Context, cli *client.Client) (*sssoapi.TokenResponse, error) {
	username := c.PostForm("username")
	password := c.PostForm("password")
	clientID := c.PostForm("client_id")
	scope := c.PostForm("scope")

	if username == "" || password == "" || clientID == "" {
		return nil, errors.NewInvalidRequest("missing required parameters. " +
			"Required parameters: username, password, client_id")
	}

	ctx := c.Request.Context()

	return oa.service.PasswordGrant(ctx, username, password, scope, cli)
}

func (oa *OAuth2API) handleClientCredentialsGrant(c *gin.Context, cli *client.Client) (*sssoapi.TokenResponse, error) {
	scope := c.PostForm("scope")

	ctx := c.Request.Context()

	return oa.service.ClientCredentials(ctx, cli.ID, cli.Secret, scope)
}

func (oa *OAuth2API) handleRefreshTokenGrant(c *gin.Context, cli *client.Client) (*sssoapi.TokenResponse, error) {
	refreshToken := c.PostForm("refresh_token")
	if refreshToken == "" {
		return nil, errors.NewInvalidRequest("refresh_token is required")
	}

	ctx := c.Request.Context()

	return oa.service.RefreshToken(ctx, refreshToken, cli.ID)
}

// IntrospectHandler implements RFC 7662 Token Introspection. It checks for required parameters
// (client_id, client_secret, and token), authenticates the client, and then calls the
// IntrospectToken method to inspect the token. If the introspection fails, it returns
// a 200 OK response with active=false as per the RFC. Otherwise, it returns the introspection result.
func (oa *OAuth2API) IntrospectHandler(c *gin.Context) {
	// Token introspection requires authentication
	clientID := c.PostForm("client_id")
	clientSecret := c.PostForm("client_secret")

	if clientID == "" || clientSecret == "" {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "invalid_client",
		})
		return
	}

	token := c.PostForm("token")
	if token == "" {
		c.JSON(http.StatusBadRequest, errors.NewInvalidRequest("token parameter is required"))
		return
	}

	tokenType := c.PostForm("token_type_hint")

	ctx := c.Request.Context()

	introspection, err := oa.service.IntrospectToken(ctx, token, tokenType, clientID, clientSecret)
	if err != nil {
		log.Error().Err(err).Msg("token introspection failed")
		// According to RFC 7662, we should still return 200 OK with active=false
		c.JSON(http.StatusOK, gin.H{
			"active": false,
		})
		return
	}

	c.JSON(http.StatusOK, introspection)
}
