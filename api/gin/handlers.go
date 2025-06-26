//nolint:varnamelen,tagliatelle
package sssogin

import (
	goerrors "errors" // Standard Go errors package
	"fmt"
	"html/template" // Added for HTML rendering
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	ssso "github.com/pilab-dev/shadow-sso"
	sssoapi "github.com/pilab-dev/shadow-sso/api"
	"github.com/pilab-dev/shadow-sso/client"
	"net/url"
	"time"

	"github.com/google/uuid"
	"github.com/pilab-dev/shadow-sso/domain"
	ssoerrors "github.com/pilab-dev/shadow-sso/errors" // Custom errors
	"github.com/pilab-dev/shadow-sso/internal/metrics" // For custom metrics
	"github.com/pilab-dev/shadow-sso/internal/oidcflow"
	"github.com/pilab-dev/shadow-sso/services"
	"github.com/rs/zerolog/log"
)

const (
	// SessionCookieName is the name of the cookie used to store the OIDC provider's user session.
	SessionCookieName = "sso_op_session"
	// CSRFCookieName is the name of the cookie used for CSRF protection.
	CSRFCookieName = "sso_csrf_token"
	// CSRFHeaderName is the name of the HTTP header used to carry the CSRF token.
	CSRFHeaderName = "X-CSRF-Token"
)

// OAuth2API struct to hold dependencies.
type OAuth2API struct {
	service          *services.OAuthService
	jwksService      *services.JWKSService
	clientService    *client.ClientService
	pkceService      *services.PKCEService
	config           *ssso.OpenIDProviderConfig
	flowStore        *oidcflow.InMemoryFlowStore
	userSessionStore *oidcflow.InMemoryUserSessionStore
	userRepo         domain.UserRepository
	passwordHasher   services.PasswordHasher
}

// NewOAuth2API initializes the OAuth2 API.
func NewOAuth2API(
	service *services.OAuthService,
	jwksService *services.JWKSService,
	clientService *client.ClientService,
	pkceService *services.PKCEService,
	config *ssso.OpenIDProviderConfig,
	flowStore *oidcflow.InMemoryFlowStore,
	userSessionStore *oidcflow.InMemoryUserSessionStore,
	userRepo domain.UserRepository,
	passwordHasher services.PasswordHasher,
) *OAuth2API {
	if config == nil {
		// This default issuer should ideally be configurable or removed if always provided by caller.
		config = ssso.NewDefaultConfig("https://sso.pilab.hu")
	}
	if config.NextJSLoginURL == "" {
		// A default or a panic might be appropriate if this is critical and not set.
		// For now, we'll allow it to be empty, but handlers using it will need to check.
		log.Warn().Msg("NextJSLoginURL is not configured in OpenIDProviderConfig. Redirects to Next.js UI will not work.")
	}
	return &OAuth2API{
		service:          service,
		jwksService:      jwksService,
		clientService:    clientService,
		pkceService:      pkceService,
		config:           config,
		flowStore:        flowStore,
		userSessionStore: userSessionStore,
		userRepo:         userRepo,
		passwordHasher:   passwordHasher,
	}
}

// RegisterRoutes registers the OAuth2 routes.
func (oa *OAuth2API) RegisterRoutes(e *gin.Engine) {
	// Apply security headers middleware to all routes
	e.Use(SecurityHeadersMiddleware())

	e.POST("/oauth2/token", oa.TokenHandler)
	e.GET("/oauth2/authorize", oa.AuthorizeHandler)
	e.POST("/oauth2/device_authorization", oa.DeviceAuthorizationHandler)
	e.GET("/oauth2/userinfo", oa.UserInfoHandler)
	e.POST("/oauth2/revoke", oa.RevokeHandler)
	e.POST("/oauth2/introspect", oa.IntrospectHandler)

	// OpenID Configuration endpoints
	e.GET("/.well-known/openid-configuration", oa.OpenIDConfigurationHandler)
	e.GET("/.well-known/jwks.json", oa.JWKSHandler)

	// Device Verification User-Facing Endpoints
	deviceGroup := e.Group("/oauth2/device")
	{
		// Assuming some auth middleware (e.g., EnsureAuthenticated) might be applied to this group or individual routes.
		// For this subtask, handlers will manually check for userID in context.
		deviceGroup.GET("/verify", oa.DeviceVerificationPageHandler)
		deviceGroup.POST("/verify", oa.DeviceVerificationSubmitHandler)
	}

	// API Endpoints for Next.js UI driven OIDC flow
	oidcAPIGroup := e.Group("/api/oidc")
	{
		oidcAPIGroup.GET("/flow/:flowId", oa.GetFlowDetailsHandler)
		oidcAPIGroup.POST("/authenticate", oa.AuthenticateUserHandler)
		// TODO: Add CSRF protection middleware to /authenticate if possible, or handle in handler.
	}
}

// ... (DeviceAuthorizationHandler, TokenHandler, handleDeviceCodeGrant, etc. - no changes here) ...

const deviceVerificationHTML = `
<!DOCTYPE html>
<html>
<head>
    <title>Activate Device</title>
    <style>
        body { font-family: sans-serif; display: flex; flex-direction: column; align-items: center; justify-content: center; min-height: 90vh; background-color: #f4f4f4; color: #333; }
        .container { background-color: #fff; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); text-align: center; }
        input[type="text"] { padding: 10px; margin-bottom: 15px; border: 1px solid #ddd; border-radius: 4px; width: calc(100%% - 22px); }
        button { padding: 10px 20px; background-color: #007bff; color: white; border: none; border-radius: 4px; cursor: pointer; }
        button:hover { background-color: #0056b3; }
        .message { margin-top: 20px; padding: 10px; border-radius: 4px; }
        .error { background-color: #f8d7da; color: #721c24; border: 1px solid #f5c6cb;}
        .success { background-color: #d4edda; color: #155724; border: 1px solid #c3e6cb;}
        .user-code-display { font-size: 1.2em; font-weight: bold; margin-bottom: 15px; color: #555; }
    </style>
</head>
<body>
    <div class="container">
        <h2>Activate Device</h2>
        <p>Please enter the code displayed on your device.</p>
        {{if .UserCodePreFill}}
        <p class="user-code-display">Code: {{.UserCodePreFill}}</p>
        <form method="POST" action="/oauth2/device/verify">
            <input type="hidden" name="user_code" value="{{.UserCodePreFill}}" />
            <button type="submit">Confirm Activation</button>
        </form>
        {{else}}
        <form method="POST" action="/oauth2/device/verify">
            <input type="text" name="user_code" placeholder="Enter code (e.g., ABCD-EFGH)" required autofocus />
            <button type="submit">Submit</button>
        </form>
        {{end}}
        {{if .Message}}
        <div class="message {{.MessageType}}">{{.Message}}</div>
        {{end}}
    </div>
</body>
</html>`

var deviceVerificationTemplate = template.Must(template.New("deviceVerify").Parse(deviceVerificationHTML))

// DeviceVerificationPageHandler serves the HTML page for user to enter their device code.
// It can optionally pre-fill the user_code if provided as a query parameter.
func (oa *OAuth2API) DeviceVerificationPageHandler(c *gin.Context) {
	// This endpoint must be accessed by an authenticated user.
	// For now, we'll simulate checking for a userID. A real app uses middleware.
	_, userIDExists := c.Get("userID") // Example: userID set by auth middleware
	if !userIDExists {
		// In a real app, redirect to login page with a `return_to` parameter.
		// For now, show an error or a simplified login prompt.
		log.Warn().Msg("DeviceVerificationPageHandler: User not authenticated. Cannot display verification page.")
		c.HTML(http.StatusUnauthorized, "deviceVerify", gin.H{
			"Message":     "You must be logged in to activate a device.",
			"MessageType": "error",
		})
		return
	}

	userCode := c.Query("user_code") // Allow pre-filling from query param e.g. /device/verify?user_code=XXXX-YYYY

	c.Header("Content-Type", "text/html; charset=utf-8")
	data := gin.H{
		"UserCodePreFill": userCode,
	}
	err := deviceVerificationTemplate.Execute(c.Writer, data)
	if err != nil {
		log.Error().Err(err).Msg("Failed to render device verification page template")
		c.String(http.StatusInternalServerError, "Error rendering page")
	}
}

// DeviceVerificationSubmitHandler handles the submission of the device code by the user.
func (oa *OAuth2API) DeviceVerificationSubmitHandler(c *gin.Context) {
	userCode := c.PostForm("user_code")
	if userCode == "" {
		c.Header("Content-Type", "text/html; charset=utf-8")
		err := deviceVerificationTemplate.Execute(c.Writer, gin.H{
			"Message":     "User code cannot be empty.",
			"MessageType": "error",
		})
		if err != nil {
			log.Error().Err(err).Msg("Failed to render template for empty user code")
		}
		return
	}

	// This endpoint MUST be accessed by an authenticated user.
	// The userID should be available from the session or a JWT token processed by middleware.
	// Example: userID, ok := c.Get("userID").(string)
	userIDVal, userIDExists := c.Get("userID") // Assume userID is string
	if !userIDExists {
		log.Error().Msg("DeviceVerificationSubmitHandler: User not authenticated. Cannot verify code.")
		c.Header("Content-Type", "text/html; charset=utf-8")
		err := deviceVerificationTemplate.Execute(c.Writer, gin.H{
			"UserCodePreFill": userCode, // Keep the code in the form
			"Message":         "Authentication required. Please log in to activate your device.",
			"MessageType":     "error",
		})
		if err != nil {
			log.Error().Err(err).Msg("Failed to render template for auth required")
		}
		return
	}
	userID, ok := userIDVal.(string)
	if !ok || userID == "" {
		log.Error().Interface("userIDVal", userIDVal).Msg("DeviceVerificationSubmitHandler: UserID is not a string or is empty.")
		c.Header("Content-Type", "text/html; charset=utf-8")
		err := deviceVerificationTemplate.Execute(c.Writer, gin.H{
			"UserCodePreFill": userCode,
			"Message":         "Invalid user session. Please log in again.",
			"MessageType":     "error",
		})
		if err != nil {
			log.Error().Err(err).Msg("Failed to render template for invalid session")
		}
		return
	}

	ctx := c.Request.Context()
	_, err := oa.service.VerifyUserCode(ctx, userCode, userID)

	renderData := gin.H{"UserCodePreFill": userCode} // Keep code in display if re-showing form context

	if err != nil {
		log.Warn().Err(err).Str("userID", userID).Msg("Failed to verify user code")
		renderData["MessageType"] = "error"
		if goerrors.Is(err, ssoerrors.ErrUserCodeNotFound) {
			renderData["Message"] = "Invalid or expired code. Please check the code and try again."
		} else if goerrors.Is(err, ssoerrors.ErrCannotApproveDeviceAuth) {
			// This might mean it was already used, or status wasn't pending.
			renderData["Message"] = "This code cannot be used. It might have already been activated or is invalid."
		} else {
			renderData["Message"] = "An unexpected error occurred. Please try again later."
		}
		c.Header("Content-Type", "text/html; charset=utf-8")
		tmplErr := deviceVerificationTemplate.Execute(c.Writer, renderData)
		if tmplErr != nil {
			log.Error().Err(tmplErr).Msg("Failed to render template for verification error")
		}
		return
	}

	log.Info().Str("user_code", userCode).Str("userID", userID).Msg("Device code successfully verified and linked to user.")
	renderData["MessageType"] = "success"
	renderData["Message"] = "Device activated successfully! You can now return to your device."
	// Optionally, remove UserCodePreFill if success, so form is clear if they land here again.
	renderData["UserCodePreFill"] = ""

	c.Header("Content-Type", "text/html; charset=utf-8")
	tmplErr := deviceVerificationTemplate.Execute(c.Writer, renderData)
	if tmplErr != nil {
		log.Error().Err(tmplErr).Msg("Failed to render template for verification success")
	}
}

// DeviceAuthorizationHandler handles POST /oauth2/device_authorization
func (oa *OAuth2API) DeviceAuthorizationHandler(c *gin.Context) {
	clientID := c.PostForm("client_id")
	scope := c.PostForm("scope") // Optional

	if clientID == "" {
		c.JSON(http.StatusBadRequest, ssoerrors.NewInvalidRequest("client_id is required"))
		return
	}

	ctx := c.Request.Context()

	verificationBaseURI := oa.config.Issuer // Changed from BaseURL to Issuer
	if verificationBaseURI == "" {
		// Attempt to construct from request if not configured, ensure https if in production
		scheme := "http"
		if c.Request.TLS != nil || c.GetHeader("X-Forwarded-Proto") == "https" {
			scheme = "https"
		}
		verificationBaseURI = fmt.Sprintf("%s://%s", scheme, c.Request.Host)
		log.Warn().Str("uri", verificationBaseURI).Msg("BaseURL not configured, derived from request for device verification URI.")
	}

	resp, err := oa.service.InitiateDeviceAuthorization(ctx, clientID, scope, verificationBaseURI)
	if err != nil {
		// Check if the error is an OAuth2Error type from ssoerrors package
		if oauthErr, ok := err.(*ssoerrors.OAuth2Error); ok {
			// Use the Code field for the error type and Description for the message
			// Assuming NewInvalidClient returns an OAuth2Error with Code "invalid_client"
			if oauthErr.Code == ssoerrors.InvalidClient {
				c.JSON(http.StatusUnauthorized, oauthErr) // Return the full OAuth2Error
				return
			}
		}
		// Fallback for other errors. The type assertion above should handle ssoerrors.NewInvalidClient.
		log.Error().Err(err).Msg("Failed to initiate device authorization")
		c.JSON(http.StatusInternalServerError, ssoerrors.NewServerError("Failed to initiate device authorization"))
		return
	}

	c.Header("Cache-Control", "no-store")
	c.Header("Pragma", "no-cache")
	c.JSON(http.StatusOK, resp)
}

// AuthorizeHandler handles OAuth 2.0 authorization requests. It validates the client, redirect URI,
// response type, scope, and PKCE (Proof Key for Code Exchange) requirements. If all validations pass,
// it generates an authorization code and redirects the user to the provided redirect URI with the code.
//
//nolint:funlen,gocognit
func (oa *OAuth2API) AuthorizeHandler(c *gin.Context) {
	ctx := c.Request.Context()

	// Extract OIDC parameters
	clientID := c.Query("client_id")
	redirectURI := c.Query("redirect_uri")
	responseType := c.Query("response_type")
	scopeQuery := c.Query("scope")
	state := c.Query("state")
	nonce := c.Query("nonce") // OIDC
	codeChallenge := c.Query("code_challenge")
	codeChallengeMethod := c.Query("code_challenge_method")
	// prompt := c.Query("prompt") // e.g., none, login, consent, select_account

	// Basic validation of required OAuth2 parameters
	if clientID == "" || redirectURI == "" || responseType == "" {
		oa.sendJSONError(c, http.StatusBadRequest, ssoerrors.NewInvalidRequest("client_id, redirect_uri, and response_type are required"))
		return
	}
	if responseType != "code" {
		oa.sendJSONError(c, http.StatusBadRequest, ssoerrors.NewInvalidRequest("unsupported response_type, only 'code' is supported"))
		return
	}

	// Validate client and redirect URI (critical for security)
	_, err := oa.clientService.GetClient(ctx, clientID) // rpClient was declared but not used. Changed to _
	if err != nil {
		log.Warn().Err(err).Str("client_id", clientID).Msg("AuthorizeHandler: Invalid client_id")
		oa.sendJSONError(c, http.StatusBadRequest, ssoerrors.NewInvalidClient("invalid client_id"))
		return
	}
	if err := oa.clientService.ValidateRedirectURI(ctx, clientID, redirectURI); err != nil {
		log.Warn().Err(err).Str("client_id", clientID).Str("redirect_uri", redirectURI).Msg("AuthorizeHandler: Invalid redirect_uri")
		oa.sendJSONError(c, http.StatusBadRequest, ssoerrors.NewInvalidRequest("invalid redirect_uri"))
		return
	}

	// Validate scope
	if err := oa.clientService.ValidateScope(ctx, clientID, strings.Split(scopeQuery, " ")); err != nil {
		log.Warn().Err(err).Str("client_id", clientID).Str("scope", scopeQuery).Msg("AuthorizeHandler: Invalid scope")
		oa.sendJSONError(c, http.StatusBadRequest, ssoerrors.NewInvalidScope("invalid scope requested"))
		return
	}

	// PKCE Validation (presence of challenge if client requires it)
	requiresPKCE, _ := oa.clientService.RequiresPKCE(ctx, clientID) // Error already handled by GetClient
	if requiresPKCE {
		if codeChallenge == "" {
			log.Warn().Str("client_id", clientID).Msg("AuthorizeHandler: PKCE code_challenge required but not provided")
			oa.sendJSONError(c, http.StatusBadRequest, ssoerrors.NewPKCERequired())
			return
		}
		if codeChallengeMethod != "S256" && codeChallengeMethod != "" && codeChallengeMethod != "plain" { // "" defaults to plain if allowed, or S256 if plain disabled
			log.Warn().Str("client_id", clientID).Str("method", codeChallengeMethod).Msg("AuthorizeHandler: Invalid code_challenge_method")
			oa.sendJSONError(c, http.StatusBadRequest, ssoerrors.NewInvalidRequest("invalid code_challenge_method, only S256 or plain (if enabled) are supported"))
			return
		}
		// If method is empty, and plain is disabled, server should default to S256 or reject.
		// Assuming PKCEService or config handles this logic if method is empty.
		// For now, we just ensure it's one of the valid ones if provided.
	}

	// Check for existing OP user session
	sessionCookie, err := c.Cookie(SessionCookieName)
	if err == nil && sessionCookie != "" {
		userSession, sessionErr := oa.userSessionStore.GetUserSession(sessionCookie)
		if sessionErr == nil {
			// User is logged in to OP. Proceed to generate auth code.
			// TODO: Handle 'prompt=login' - if present, must re-authenticate even if session exists.
			// TODO: Handle consent - if not previously given for this client/scopes, may need a consent step.

			log.Info().Str("userID", userSession.UserID).Str("clientID", clientID).Msg("AuthorizeHandler: User already authenticated by OP session. Proceeding to auth code generation.")
			authCode, errGen := oa.service.GenerateAuthCode(
				ctx,
				clientID,
				userSession.UserID, // Pass UserID from OP session
				redirectURI,
				scopeQuery,
				codeChallenge,
				codeChallengeMethod,
			)
			if errGen != nil {
				log.Error().Err(errGen).Msg("AuthorizeHandler: Failed to generate authorization code for authenticated user")
				oa.sendJSONError(c, http.StatusInternalServerError, ssoerrors.NewServerError("failed to generate authorization code"))
				return
			}
			oa.redirectToClient(c, redirectURI, authCode, state)
			return
		}
		// Corrected to use goerrors.Is as per import alias
		if !goerrors.Is(sessionErr, oidcflow.ErrSessionNotFound) && !goerrors.Is(sessionErr, oidcflow.ErrSessionExpired) {
			log.Warn().Err(sessionErr).Msg("AuthorizeHandler: Error validating existing OP session cookie")
		}
		// If session not found or expired, clear the bad cookie and proceed to login flow
		oa.clearUserSessionCookie(c)
	}

	// No active OP session or 'prompt=login' requires redirect to Next.js UI
	if oa.config.NextJSLoginURL == "" {
		log.Error().Msg("AuthorizeHandler: NextJSLoginURL is not configured. Cannot redirect to external UI.")
		oa.sendJSONError(c, http.StatusInternalServerError, ssoerrors.NewServerError("authentication UI not configured"))
		return
	}

	flowID := uuid.NewString()
	flowState := oidcflow.LoginFlowState{
		FlowID:              flowID,
		ClientID:            clientID,
		RedirectURI:         redirectURI,
		Scope:               scopeQuery,
		State:               state,
		Nonce:               nonce,
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: codeChallengeMethod,
		ExpiresAt:           time.Now().Add(10 * time.Minute), // Flow valid for 10 minutes
		OriginalOIDCParams:  oa.extractOriginalOIDCParams(c),
	}

	if err := oa.flowStore.StoreFlow(flowID, flowState); err != nil {
		log.Error().Err(err).Msg("AuthorizeHandler: Failed to store OIDC flow state")
		oa.sendJSONError(c, http.StatusInternalServerError, ssoerrors.NewServerError("failed to initiate login flow"))
		return
	}

	// TODO: Set CSRF cookie here before redirecting to Next.js UI.
	// csrfToken := uuid.NewString()
	// http.SetCookie(c.Writer, &http.Cookie{Name: CSRFCookieName, Value: csrfToken, Expires: time.Now().Add(10 * time.Minute), HttpOnly: true, Path: "/" ...})

	nextJSLoginURL, _ := url.Parse(oa.config.NextJSLoginURL)
	query := nextJSLoginURL.Query()
	query.Set("flowId", flowID)
	// Potentially pass client_id or other safe context if Next.js UI needs it directly for display before calling /api/oidc/flow
	// query.Set("client_id", clientID)
	nextJSLoginURL.RawQuery = query.Encode()

	log.Info().Str("flowId", flowID).Str("nextjs_url", nextJSLoginURL.String()).Msg("AuthorizeHandler: Redirecting user to Next.js for authentication.")
	c.Redirect(http.StatusFound, nextJSLoginURL.String())
}

// sendJSONError is a helper to return JSON errors consistently.
func (oa *OAuth2API) sendJSONError(c *gin.Context, statusCode int, errDetails *ssoerrors.OAuth2Error) {
	// Ensure Content-Type is application/json for error responses
	// Some clients might expect this, especially for OAuth errors.
	// However, /authorize typically redirects or shows HTML.
	// For initial validation errors before redirect, JSON might be acceptable.
	// If an HTML error page is preferred, this helper would need to change.
	c.JSON(statusCode, errDetails)
}

// redirectToClient is a helper to redirect back to the client's redirect_uri.
func (oa *OAuth2API) redirectToClient(c *gin.Context, baseRedirectURI, code, state string) {
	parsedRedirectURI, err := url.Parse(baseRedirectURI)
	if err != nil {
		log.Error().Err(err).Str("redirect_uri", baseRedirectURI).Msg("Failed to parse base redirect URI")
		oa.sendJSONError(c, http.StatusInternalServerError, ssoerrors.NewServerError("internal error constructing redirect"))
		return
	}

	params := url.Values{}
	params.Set("code", code)
	if state != "" {
		params.Set("state", state)
	}

	// OIDC spec recommends params in query for "code" response_type
	parsedRedirectURI.RawQuery = params.Encode()
	c.Redirect(http.StatusFound, parsedRedirectURI.String())
}

// clearUserSessionCookie invalidates the OP user session cookie.
func (oa *OAuth2API) clearUserSessionCookie(c *gin.Context) {
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     SessionCookieName,
		Value:    "",
		Expires:  time.Unix(0, 0), // Expire immediately
		HttpOnly: true,
		Path:     "/",
		Secure:   c.Request.TLS != nil,
		SameSite: http.SameSiteLaxMode,
	})
}

// extractOriginalOIDCParams extracts all query parameters from the request.
func (oa *OAuth2API) extractOriginalOIDCParams(c *gin.Context) map[string]string {
	params := make(map[string]string)
	for key, values := range c.Request.URL.Query() {
		if len(values) > 0 {
			params[key] = values[0] // Take the first value for simplicity
		}
	}
	return params
}


// GrantType enumeration for OAuth2 grant types.
type GrantType string

const (
	GrantTypeAuthorizationCode GrantType = "authorization_code"
	GrantTypeRefreshToken      GrantType = "refresh_token"
	GrantTypeClientCredentials GrantType = "client_credentials"
	GrantTypePassword          GrantType = "password"
	GrantTypeDeviceCode        GrantType = "urn:ietf:params:oauth:grant-type:device_code" // New
)

// TokenHandler handles OAuth2 token requests. It:
//   - Extracts client_id, client_secret, and grant_type from the request form values.
//   - Validates the client credentials and grant type.
//   - Processes the grant type by calling one of three handler functions based on the
//     grant type (authorization_code, refresh_token, or client_credentials).
//   - Returns a JSON response with the token response if successful, or an error response
//     if any of the validation or processing steps fail.
//
//nolint:funlen,gocognit
func (oa *OAuth2API) TokenHandler(c *gin.Context) {
	clientID := c.PostForm("client_id")
	clientSecret := c.PostForm("client_secret")
	grantType := c.PostForm("grant_type")

	ctx := c.Request.Context()
	var cli *client.Client
	var err error // Keep err scoped within this function initially

	isDeviceCodeGrant := GrantType(grantType) == GrantTypeDeviceCode

	if clientID == "" {
		c.JSON(http.StatusBadRequest, ssoerrors.NewInvalidRequest("client_id is required"))
		return
	}

	// Client Authentication:
	if clientSecret != "" {
		cli, err = oa.clientService.ValidateClient(ctx, clientID, clientSecret)
		if err != nil {
			log.Error().Err(err).Msg("Invalid client credentials")
			c.JSON(http.StatusUnauthorized, ssoerrors.NewInvalidClient("Invalid client credentials"))
			return
		}
	} else {
		cli, err = oa.clientService.GetClient(ctx, clientID)
		if err != nil {
			log.Error().Err(err).Str("client_id", clientID).Msg("Client not found")
			c.JSON(http.StatusBadRequest, ssoerrors.NewInvalidClient("Invalid client_id"))
			return
		}
		// Assuming client.Client has IsConfidential() method. If not, this check needs adjustment.
		// For now, let's assume a helper or direct field access like 'cli.Confidential'.
		// This is a placeholder for actual IsConfidential() check.
		isConfidentialClient := false // Placeholder: Replace with actual check e.g. cli.IsConfidential()
		if !isDeviceCodeGrant && isConfidentialClient {
			log.Error().Str("client_id", clientID).Msg("Client is confidential but no secret provided")
			c.JSON(http.StatusUnauthorized, ssoerrors.NewInvalidClient("Client secret required for confidential client"))
			return
		}
	}

	// Validate grant type (check if this client is allowed to use this grant type)
	if err := oa.clientService.ValidateGrantType(ctx, clientID, grantType); err != nil {
		log.Error().Err(err).Msg("Grant type not allowed for this client")
		c.JSON(http.StatusBadRequest, ssoerrors.NewUnauthorizedClient("Grant type not allowed for this client"))
		return
	}

	var tokenResponse *sssoapi.TokenResponse
	var processErr error

	switch GrantType(grantType) {
	case GrantTypeAuthorizationCode:
		tokenResponse, processErr = oa.handleAuthorizationCodeGrant(c, cli)
	case GrantTypeRefreshToken:
		tokenResponse, processErr = oa.handleRefreshTokenGrant(c, cli)
	case GrantTypeClientCredentials:
		tokenResponse, processErr = oa.handleClientCredentialsGrant(c, cli)
	case GrantTypePassword:
		tokenResponse, processErr = oa.handlePasswordGrant(c, cli)
	case GrantTypeDeviceCode:
		tokenResponse, processErr = oa.handleDeviceCodeGrant(c, cli)
	default:
		c.JSON(http.StatusBadRequest, ssoerrors.NewUnsupportedGrantType())
		return
	}

	if processErr != nil {
		if c.Writer.Written() {
			return
		}
		// Try to assert to ssoerrors.OAuth2Error first
		if oauthErr, ok := processErr.(*ssoerrors.OAuth2Error); ok {
			log.Error().Err(oauthErr).Str("code", oauthErr.Code).Msg("Token generation failed (OAuth2Error)")
			// Assuming OAuth2Error has a field like `HTTPStatusCode` or we map codes to status
			// For now, default to Bad Request for many, but could be Unauthorized for invalid_client etc.
			statusCode := http.StatusBadRequest
			if oauthErr.Code == ssoerrors.InvalidClient || oauthErr.Code == ssoerrors.UnauthorizedClient {
				statusCode = http.StatusUnauthorized
			}
			c.JSON(statusCode, oauthErr)
			return
		}
		// The check for ssoerrors.ErrInvalidRequest or ssoerrors.ErrInvalidGrant using goerrors.Is
		// is likely incorrect if these are not actual exported error variables.
		// The *ssoerrors.OAuth2Error type assertion above should handle these if processErr is of that type
		// and its .Code field matches ssoerrors.InvalidRequest or ssoerrors.InvalidGrant.
		// If they are some other kind of error that should map to NewInvalidGrant, that's a different scenario.
		// For now, removing this specific block as it's causing undefined errors.

		log.Error().Err(processErr).Msg("Token generation failed (Non-OAuth2Error)")
		c.JSON(http.StatusInternalServerError, ssoerrors.NewServerError("Failed to generate token: "+processErr.Error()))
		return
	}

	// If we reach here, processErr is nil.
	// The sub-handlers for device_code grant might write the response directly.
	if c.Writer.Written() {
		// If response already written (e.g., by handleDeviceCodeGrant for pending/slow_down),
		// it means the sub-handler took control of the response. We should just return.
		// The sub-handler is responsible for its own logging if needed.
		return
	}

	// If tokenResponse is nil and response wasn't written by a sub-handler, it's an internal error.
	if tokenResponse == nil {
		log.Error().Str("client_id", clientID).Str("grant_type", grantType).Msg("Token response is nil after grant processing and response not written by sub-handler")
		c.JSON(http.StatusInternalServerError, ssoerrors.NewServerError("Internal error during token generation"))
		return
	}

	// Log successful token generation with details
	log.Info().
		Str("client_id", clientID).
		Str("grant_type", grantType).
		Int("expires_in", tokenResponse.ExpiresIn).
		Str("token_type", tokenResponse.TokenType).
		// AccessToken and RefreshToken are sensitive, consider logging only their presence or a hash.
		// For this consolidation, matching Echo's detail by logging presence.
		Bool("access_token_present", tokenResponse.AccessToken != "").
		Bool("refresh_token_present", tokenResponse.RefreshToken != "").
		Bool("id_token_present", tokenResponse.IDToken != "").
		Msg("Token generated")

	// Set headers and send response
	c.Header("Cache-Control", "no-store")
	c.Header("Pragma", "no-cache")
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

	// ctx := c.Request.Context() // Removed unused ctx

	// Get bearer token
	tokenParts := strings.Split(authHeader, " ")
	if len(tokenParts) != 2 || tokenParts[0] != "Bearer" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_token"})
		return
	}
	// token := tokenParts[1] // Removed unused token

	// Validate token, and get user info
	// TODO: Implement UserInfo endpoint correctly.
	// This should involve validating the token and then fetching claims.
	// The OAuthService.GetUserInfo method was removed as it was a stub.
	// This functionality likely belongs in AuthService or a dedicated UserInfoService.
	// For now, returning a placeholder or an error.
	// userInfo, err := oa.service.GetUserInfo(ctx, token)
	// if err != nil {
	// 	c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_token"})
	// 	return
	// }
	// c.JSON(http.StatusOK, userInfo)
	log.Error().Msg("UserInfoHandler: GetUserInfo not implemented")
	c.JSON(http.StatusNotImplemented, gin.H{"error": "not_implemented", "error_description": "Userinfo endpoint is not yet fully implemented."})
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
		c.JSON(http.StatusBadRequest, ssoerrors.NewInvalidRequest("token parameter is required"))
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
		c.JSON(http.StatusBadRequest, ssoerrors.NewInvalidRequest("client_id parameter is required"))
		return
	}
	// Note: client_secret might be optional for public clients.
	// The service.RevokeToken will ultimately decide based on client's configuration.

	ctx := c.Request.Context()

	err := oa.service.RevokeToken(ctx, token, tokenTypeHint, clientID, clientSecret)
	if err != nil {
		// Check for specific OAuth errors to return appropriate status codes
		if oerr, ok := err.(*ssoerrors.OAuth2Error); ok { // Use ssoerrors.OAuth2Error
			// Compare with error codes from ssoerrors
			if oerr.Code == ssoerrors.InvalidClient || oerr.Code == ssoerrors.UnauthorizedClient { // Example comparison
				log.Warn().Err(err).Str("client_id", clientID).Msg("Client authentication failed during token revocation")
				c.JSON(http.StatusUnauthorized, oerr)
				return
			}
			// For other OAuth2 specific errors that are client's fault
			log.Warn().Err(err).Str("client_id", clientID).Str("token_type_hint", tokenTypeHint).Msg("OAuth error during token revocation")
			c.JSON(http.StatusBadRequest, oerr) // Default to Bad Request for other client errors
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
		c.JSON(http.StatusInternalServerError, ssoerrors.NewServerError("Internal server error")) // Use ssoerrors.NewServerError
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
	if cfg.EnabledEndpoints.DeviceAuthorization { // Check if Device Authorization endpoint is enabled
		resp.DeviceAuthorizationEndpoint = ToPtr(baseURL + "/oauth2/device_authorization")
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
	resp.RequestParameterSupported = true    // Default or from cfg if available
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

// uniqueStrings helper function to remove duplicates from a slice of strings
func uniqueStrings(slice []string) []string {
	keys := make(map[string]bool)
	list := []string{}
	for _, entry := range slice {
		if _, value := keys[entry]; !value {
			keys[entry] = true
			list = append(list, entry)
		}
	}
	return list
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
			return nil, ssoerrors.NewPKCERequired()
		}
		if err := oa.pkceService.ValidateCodeVerifier(ctx, code, codeVerifier); err != nil {
			return nil, ssoerrors.NewInvalidPKCE(err.Error())
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
		return nil, ssoerrors.NewInvalidRequest("missing required parameters. " +
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
		return nil, ssoerrors.NewInvalidRequest("refresh_token is required")
	}

	ctx := c.Request.Context()

	tokenResponse, err := oa.service.RefreshToken(ctx, refreshToken, cli.ID)
	if err == nil && tokenResponse != nil {
		metrics.TokensRefreshedTotal.Inc()
	}
	return tokenResponse, err
}

// handleDeviceCodeGrant is called by TokenHandler for device_code grant type
func (oa *OAuth2API) handleDeviceCodeGrant(c *gin.Context, cli *client.Client) (*sssoapi.TokenResponse, error) {
	deviceCode := c.PostForm("device_code")
	requestClientID := c.PostForm("client_id") // client_id from form body

	if deviceCode == "" {
		return nil, ssoerrors.NewInvalidRequest("device_code is required")
	}
	// client_id is also required in the body for device_code grant (RFC 8628 Sec 3.4)
	if requestClientID == "" {
		return nil, ssoerrors.NewInvalidRequest("client_id is required in request body for device_code grant")
	}
	// Ensure the client_id in the body matches the authenticated client
	// cli.ID comes from client authentication (if confidential) or from client_id in body (if public)
	if cli != nil && requestClientID != cli.ID {
		// This case implies client_id in body doesn't match client_id used for auth (if any)
		// or if a public client sent client_id in body that doesn't match the one resolved by GetClient earlier
		return nil, ssoerrors.NewInvalidGrant("client_id in request body does not match client_id used for request")
	}

	ctx := c.Request.Context()
	// Pass cli.ID as the clientID for IssueTokenForDeviceFlow, as this is the validated/authenticated client.
	tokenResponse, err := oa.service.IssueTokenForDeviceFlow(ctx, deviceCode, cli.ID)
	if err != nil {
		// Handle specific device flow errors by writing to response and returning nil error
		// so TokenHandler knows response is handled.
		if goerrors.Is(err, ssoerrors.ErrAuthorizationPending) {
			c.Header("Cache-Control", "no-store")
			c.Header("Pragma", "no-cache")
			c.JSON(http.StatusBadRequest, gin.H{"error": "authorization_pending", "error_description": err.Error()})
			return nil, nil // Signal to TokenHandler that response is sent
		}
		if goerrors.Is(err, ssoerrors.ErrSlowDown) {
			c.Header("Cache-Control", "no-store")
			c.Header("Pragma", "no-cache")
			// HTTP 429 Too Many Requests would also be appropriate for slow_down
			c.JSON(http.StatusBadRequest, gin.H{"error": "slow_down", "error_description": err.Error()})
			return nil, nil
		}
		if goerrors.Is(err, ssoerrors.ErrDeviceFlowTokenExpired) {
			c.Header("Cache-Control", "no-store")
			c.Header("Pragma", "no-cache")
			c.JSON(http.StatusBadRequest, gin.H{"error": "expired_token", "error_description": err.Error()})
			return nil, nil
		}
		if goerrors.Is(err, ssoerrors.ErrDeviceFlowAccessDenied) {
			c.Header("Cache-Control", "no-store")
			c.Header("Pragma", "no-cache")
			c.JSON(http.StatusBadRequest, gin.H{"error": "access_denied", "error_description": err.Error()})
			return nil, nil
		}
		if oauthErr, ok := err.(*ssoerrors.OAuth2Error); ok && oauthErr.Code == ssoerrors.InvalidClient {
			c.Header("Cache-Control", "no-store")
			c.Header("Pragma", "no-cache")
			c.JSON(http.StatusUnauthorized, oauthErr) // Use StatusUnauthorized for invalid_client
			return nil, nil
		}
		// For other errors, let TokenHandler's generic error handling deal with them.
		return nil, err
	}

	return tokenResponse, nil
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
		c.JSON(http.StatusBadRequest, ssoerrors.NewInvalidRequest("token parameter is required"))
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

// GetFlowDetailsHandler allows the Next.js UI to retrieve information about an ongoing OIDC flow.
func (oa *OAuth2API) GetFlowDetailsHandler(c *gin.Context) {
	flowID := c.Param("flowId")
	if flowID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": "flowId is required"})
		return
	}

	flowState, err := oa.flowStore.GetFlow(flowID)
	if err != nil {
		if goerrors.Is(err, oidcflow.ErrFlowNotFound) { // Changed errors.Is to goerrors.Is
			c.JSON(http.StatusNotFound, gin.H{"error": "invalid_flow", "error_description": "Flow ID not found."})
			return
		}
		if goerrors.Is(err, oidcflow.ErrFlowExpired) { // Changed errors.Is to goerrors.Is
			c.JSON(http.StatusNotFound, gin.H{"error": "expired_flow", "error_description": "Flow ID has expired."})
			// Optionally delete it now
			_ = oa.flowStore.DeleteFlow(flowID)
			return
		}
		log.Error().Err(err).Str("flowId", flowID).Msg("Error retrieving flow state")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error", "error_description": "Could not retrieve flow details."})
		return
	}

	// Return only necessary, non-sensitive information to the frontend
	// For example, client_id, scope. Avoid sending back code_challenge etc. unless specifically needed by UI.
	// For this example, we'll send ClientID and Scope.
	// The actual client application details (like name) could be fetched using clientService if needed.
	client, err := oa.clientService.GetClient(c.Request.Context(), flowState.ClientID)
	if err != nil {
		log.Error().Err(err).Str("clientID", flowState.ClientID).Msg("Client not found for flow details")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error", "error_description": "Error fetching client details for flow."})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"client_id":        flowState.ClientID,
		"client_name":      client.Name, // Example: send client name
		"scope":            flowState.Scope,
		"original_params":  flowState.OriginalOIDCParams, // Send original params if UI needs them
		// Add any other details the Next.js UI might need to display context to the user.
	})
}

// AuthenticateUserRequest defines the expected JSON body for the /api/oidc/authenticate endpoint.
type AuthenticateUserRequest struct {
	FlowID   string `json:"flow_id" binding:"required"`
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required"`
	// CSRFToken string `json:"csrf_token" binding:"required"` // Add if CSRF token is sent in body
}

// AuthenticateUserHandler handles the user's login submission from the Next.js UI.
// nolint: funlen, gocognit
func (oa *OAuth2API) AuthenticateUserHandler(c *gin.Context) {
	var req AuthenticateUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": "Invalid request payload: " + err.Error()})
		return
	}

	ctx := c.Request.Context()

	// TODO: Implement CSRF Protection check here.
	// Example:
	// csrfCookie, err := c.Cookie(CSRFCookieName)
	// if err != nil || csrfCookie == "" || csrfCookie != c.GetHeader(CSRFHeaderName) { // or req.CSRFToken if in body
	// 	c.JSON(http.StatusForbidden, gin.H{"error": "invalid_csrf", "error_description": "CSRF token mismatch or missing."})
	//	return
	// }

	// Use goerrors imported as "errors" alias at the top of the file is fine.
	// The issue was that some handlers (GetFlowDetailsHandler, AuthenticateUserHandler)
	// were calling errors.Is without having "errors" (the standard library one) explicitly imported
	// within their scope if the top-level import was `goerrors "errors"`.
	// It's better to consistently use `goerrors.Is` if that's the chosen alias, or import "errors" directly.
	// The previous change to use goerrors.Is in GetFlowDetailsHandler was correct.
	// Let's ensure AuthenticateUserHandler also uses goerrors.Is for consistency.

	flowState, err := oa.flowStore.GetFlow(req.FlowID)
	if err != nil {
		if goerrors.Is(err, oidcflow.ErrFlowNotFound) || goerrors.Is(err, oidcflow.ErrFlowExpired) { // Use goerrors.Is
			desc := "Flow ID not found or expired."
			if goerrors.Is(err, oidcflow.ErrFlowExpired) { // Use goerrors.Is
				_ = oa.flowStore.DeleteFlow(req.FlowID)
			}
			c.JSON(http.StatusForbidden, gin.H{"error": "invalid_flow", "error_description": desc})
			return
		}
		log.Error().Err(err).Str("flowId", req.FlowID).Msg("Error retrieving flow state during authentication")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error", "error_description": "Could not retrieve flow details."})
		return
	}

	// Ensure flow is not already authenticated by a user
	if flowState.UserID != "" {
		log.Warn().Str("flowId", req.FlowID).Str("existingUserID", flowState.UserID).Msg("Flow already authenticated by a user.")
		// Decide behavior: error, or proceed if it's the same user re-authenticating?
		// For now, treat as an error or unexpected state.
		c.JSON(http.StatusConflict, gin.H{"error": "flow_conflict", "error_description": "This authentication flow has already been completed or is in an invalid state."})
		return
	}


	user, err := oa.userRepo.GetUserByEmail(ctx, req.Email)
	if err != nil {
		log.Warn().Err(err).Msg("User not found during Next.js UI auth attempt") // Removed email from log
		// Generic error to avoid user enumeration
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_credentials", "error_description": "Invalid email or password."})
		return
	}

	// Verify password
	if err := oa.passwordHasher.Verify(user.PasswordHash, req.Password); err != nil {
		log.Warn().Str("userID", user.ID).Msg("Incorrect password during Next.js UI auth")
		// TODO: Implement failed login attempt tracking for the user
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_credentials", "error_description": "Invalid email or password."})
		return
	}

	// TODO: Handle 2FA if enabled for the user. This would involve another step/redirect or different API call.
	// For this iteration, we assume 2FA is handled separately or not in scope for this specific handler.

	// Authentication successful, create OIDC Provider session for the user.
	sessionID := uuid.NewString()
	opSessionExpiry := time.Now().Add(24 * time.Hour) // Example: 24-hour session for the OP
	userSession := &oidcflow.UserSession{
		SessionID:       sessionID,
		UserID:          user.ID,
		AuthenticatedAt: time.Now(),
		ExpiresAt:       opSessionExpiry,
		// UserAgent:    c.Request.UserAgent(), // Optionally store
		// IPAddress:    c.ClientIP(),          // Optionally store
	}
	if err := oa.userSessionStore.StoreUserSession(userSession); err != nil {
		log.Error().Err(err).Str("userID", user.ID).Msg("Failed to store user session for OP")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error", "error_description": "Could not create user session."})
		return
	}

	// Set the OP session cookie
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     SessionCookieName,
		Value:    sessionID,
		Expires:  opSessionExpiry,
		HttpOnly: true,
		Path:     "/", // Adjust path if necessary
		Secure:   c.Request.TLS != nil, // Set Secure flag if served over HTTPS
		SameSite: http.SameSiteLaxMode,
	})

	// Update flow state with authenticated user
	flowState.UserID = user.ID
	flowState.UserAuthenticatedAt = time.Now()
	if err := oa.flowStore.UpdateFlow(req.FlowID, flowState); err != nil {
		log.Error().Err(err).Str("flowId", req.FlowID).Msg("Failed to update flow state with authenticated user")
		// This is tricky. User session is created, but flow update failed.
		// For now, log and proceed. Consider cleanup or more robust error handling.
	}

	// Generate authorization code.
	// The GenerateAuthCode method in OAuthService will need to be updated to accept UserID,
	// CodeChallenge, and CodeChallengeMethod from the flowState.
	authCode, err := oa.service.GenerateAuthCode(
		ctx,
		flowState.ClientID,
		user.ID, // Pass the authenticated UserID
		flowState.RedirectURI,
		flowState.Scope,
		flowState.CodeChallenge,       // Pass stored code challenge
		flowState.CodeChallengeMethod, // Pass stored code challenge method
	)
	if err != nil {
		log.Error().Err(err).Str("flowId", req.FlowID).Msg("Failed to generate authorization code after UI authentication")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error", "error_description": "Could not complete authorization."})
		return
	}

	// Delete the flow state as it's now been used
	_ = oa.flowStore.DeleteFlow(req.FlowID)

	// Build redirect URL back to the client application
	redirectURL := flowState.RedirectURI
	params := url.Values{}
	params.Set("code", authCode)
	if flowState.State != "" {
		params.Set("state", flowState.State)
	}

	// Check if redirectURI already has query parameters
	if strings.Contains(redirectURL, "?") {
		redirectURL += "&" + params.Encode()
	} else {
		redirectURL += "?" + params.Encode()
	}

	log.Info().Str("flowId", req.FlowID).Str("userID", user.ID).Str("redirectURL", redirectURL).Msg("User authenticated via UI, redirecting to client with auth code.")
	c.Redirect(http.StatusFound, redirectURL)
}
