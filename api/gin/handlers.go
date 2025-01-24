//nolint:varnamelen,tagliatelle
package gin

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
// The endpoint always returns 200 OK regardless of whether the token was
// successfully revoked or not.
func (oa *OAuth2API) RevokeHandler(c *gin.Context) {
	token := c.PostForm("token")
	if token == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": "token parameter is required",
		})
		return
	}

	tokenType := c.PostForm("token_type_hint")
	if tokenType == "" {
		tokenType = sssoapi.TokenTypeAccessToken
	}

	// Validate token type hint
	if tokenType != sssoapi.TokenTypeAccessToken && tokenType != sssoapi.TokenTypeRefreshToken {
		tokenType = sssoapi.TokenTypeAccessToken // Default to access_token if invalid hint
	}

	ctx := c.Request.Context()

	if err := oa.service.RevokeToken(ctx, token); err != nil {
		// According to RFC 7009 section 2.2, the authorization server SHOULD
		// respond with HTTP status code 200 even when the token was invalid
		log.Error().
			Err(err).
			Str("token_type", tokenType).
			Msg("Failed to revoke token")
	}

	c.JSON(http.StatusOK, gin.H{})
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

	//nolint:exhaustruct
	config := sssoapi.OpenIDConfiguration{
		Issuer:                baseURL,
		AuthorizationEndpoint: baseURL + "/oauth2/authorize",
		TokenEndpoint:         baseURL + "/oauth2/token",
		UserInfoEndpoint:      baseURL + "/oauth2/userinfo",
		JwksURI:               baseURL + "/.well-known/jwks.json",
		IntrospectionEndpoint: ToPtr(baseURL + "/oauth2/introspect"),
		EndSessionEndpoint:    ToPtr(baseURL + "/oauth2/logout"),
		RegistrationEndpoint:  ToPtr(baseURL + "/oauth2/register"),
		ScopesSupported:       []string{"openid", "profile", "email", "offline_access"},
		ResponseTypesSupported: []string{
			"code", "token", "id_token",
			"code token",
			"code id_token",
			"token id_token",
			"code token id_token",
		},
		ResponseModesSupported: []string{"query", "fragment", "form_post"},
		GrantTypesSupported: []string{
			"authorization_code", "implicit", "password", "refresh_token", "client_credentials",
		},
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

	c.JSON(http.StatusOK, config)
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
