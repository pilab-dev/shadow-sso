//nolint:varnamelen,tagliatelle
package openidv2_1

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	goerrors "errors"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	sssoapi "github.com/pilab-dev/shadow-sso/api"
	"github.com/pilab-dev/shadow-sso/client"

	"github.com/google/uuid"
	"github.com/pilab-dev/shadow-sso/domain"
	"github.com/pilab-dev/shadow-sso/internal/federation"
	"github.com/pilab-dev/shadow-sso/internal/metrics"
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
	service           *services.OAuthService
	jwksService       *services.JWKSService
	clientService     *client.ClientService
	pkceService       *services.PKCEService
	config            *sssoapi.OpenIDProviderConfig
	flowStore         domain.FlowStore        // Changed to domain.FlowStore
	userSessionStore  domain.UserSessionStore // Changed to domain.UserSessionStore
	userRepo          domain.UserRepository
	passwordHasher    domain.PasswordHasher  // Changed to domain.PasswordHasher
	federationService *federation.Service    // Added for LDAP and other federation flows
	tokenService      *services.TokenService // Added for issuing tokens after LDAP auth
}

type OAuth2APIOptions struct {
	OAuthService      *services.OAuthService
	JSKSService       *services.JWKSService
	ClientService     *client.ClientService
	PkceService       *services.PKCEService
	Config            *sssoapi.OpenIDProviderConfig
	FlowStore         domain.FlowStore        // Changed to domain.FlowStore
	UserSessionStore  domain.UserSessionStore // Changed to domain.UserSessionStore
	UserRepo          domain.UserRepository
	PasswordHasher    domain.PasswordHasher // Changed to domain.PasswordHasher
	FederationService *federation.Service   // Added
	TokenService      *services.TokenService
}

// NewOAuth2API initializes the OAuth2 API.
func NewOAuth2API(
	opts *OAuth2APIOptions,
) *OAuth2API {
	if opts.Config == nil {
		// This default issuer should ideally be configurable or removed if always provided by caller.
		// Note: NewDefaultConfig would need to be moved to api package or removed
		// For now, returning an error if config is nil
		log.Error().Msg("OpenIDProviderConfig is required")
		return nil
	}
	if opts.Config.NextJSLoginURL == "" {
		// A default or a panic might be appropriate if this is critical and not set.
		// For now, we'll allow it to be empty, but handlers using it will need to check.
		log.Warn().Msg("NextJSLoginURL is not configured in OpenIDProviderConfig. Redirects to Next.js UI will not work.")
	}
	return &OAuth2API{
		service:           opts.OAuthService,
		jwksService:       opts.JSKSService,
		clientService:     opts.ClientService,
		pkceService:       opts.PkceService,
		config:            opts.Config,
		flowStore:         opts.FlowStore,
		userSessionStore:  opts.UserSessionStore,
		userRepo:          opts.UserRepo,
		passwordHasher:    opts.PasswordHasher,
		federationService: opts.FederationService, // Added
		tokenService:      opts.TokenService,      // Added
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
	e.GET("/oauth2/logout", oa.LogoutHandler)
	e.POST("/oauth2/logout", oa.LogoutHandler)
	e.POST("/oauth2/register", oa.RegisterClientHandler)

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
		oidcAPIGroup.POST("/consent", oa.ConsentHandler)
	}

	// Register LDAP specific routes
	authGroup := e.Group("/auth")    // Create a common /auth group
	oa.RegisterLDAPRoutes(authGroup) // Register LDAP routes under /auth/ldap/...
	// Register other federation routes if they follow a similar pattern under /auth
	// oa.RegisterFederationCallbackRoutes(authGroup) // Example for existing federation callbacks
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
		if goerrors.Is(err, domain.ErrUserCodeNotFound) {
			renderData["Message"] = "Invalid or expired code. Please check the code and try again."
		} else if goerrors.Is(err, domain.ErrCannotApproveDeviceAuth) {
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
		c.JSON(http.StatusBadRequest, domain.NewInvalidRequest("client_id is required"))
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
		if oauthErr, ok := err.(*domain.OAuth2Error); ok {
			// Use the Code field for the error type and Description for the message
			// Assuming NewInvalidClient returns an OAuth2Error with Code "invalid_client"
			if oauthErr.Code == domain.InvalidClient {
				c.JSON(http.StatusUnauthorized, oauthErr) // Return the full OAuth2Error
				return
			}
		}
		// Fallback for other errors. The type assertion above should handle domain.NewInvalidClient.
		log.Error().Err(err).Msg("Failed to initiate device authorization")
		c.JSON(http.StatusInternalServerError, domain.NewServerError("Failed to initiate device authorization"))
		return
	}

	c.Header("Cache-Control", "no-store")
	c.Header("Pragma", "no-cache")
	c.JSON(http.StatusOK, resp)
}

// AuthorizeHandler handles OAuth 2.0 authorization requests.
// It now delegates most of its logic to helper methods.
//
//nolint:funlen,gocognit // Funlen might still be triggered but gocognit should be lower.
func (oa *OAuth2API) AuthorizeHandler(c *gin.Context) {
	ctx := c.Request.Context()

	authReqData, err := oa.parseAndValidateAuthorizeParams(c)
	if err != nil {
		// parseAndValidateAuthorizeParams is responsible for sending the JSON error
		return
	}

	if err := oa.validateClientDetails(ctx, authReqData.clientID, authReqData.redirectURI, authReqData.scopeQuery); err != nil {
		// Ensure the error being cast is actually *domain.OAuth2Error
		if oauthErr, ok := err.(*domain.OAuth2Error); ok {
			oa.sendJSONError(c, http.StatusBadRequest, oauthErr)
		} else {
			// Fallback for unexpected error types, though validateClientDetails should return ssoerrors
			log.Error().Err(err).Msg("AuthorizeHandler: Unexpected error type from validateClientDetails")
			oa.sendJSONError(c, http.StatusInternalServerError, domain.NewServerError("internal validation error"))
		}
		return
	}

	if err := oa.validatePKCE(ctx, authReqData.clientID, authReqData.codeChallenge, authReqData.codeChallengeMethod); err != nil {
		if oauthErr, ok := err.(*domain.OAuth2Error); ok {
			oa.sendJSONError(c, http.StatusBadRequest, oauthErr)
		} else {
			log.Error().Err(err).Msg("AuthorizeHandler: Unexpected error type from validatePKCE")
			oa.sendJSONError(c, http.StatusInternalServerError, domain.NewServerError("internal PKCE validation error"))
		}
		return
	}

	handledBySession, err := oa.tryHandleWithExistingSession(c, authReqData)
	// err from tryHandleWithExistingSession means an error occurred during processing (e.g. generating auth code)
	// and the response has likely already been sent by tryHandleWithExistingSession.
	if err != nil {
		// Log if necessary, but response is handled by the helper.
		return
	}
	if handledBySession {
		return
	}

	// If not handled by an existing session, redirect to external login.
	// err from initiateExternalLoginFlow means an error occurred and response sent.
	if err := oa.initiateExternalLoginFlow(c, authReqData); err != nil {
		// Log if necessary, response handled by helper.
		return
	}
}

// authorizeRequestData holds extracted and initially validated parameters from an authorization request.
type authorizeRequestData struct {
	clientID            string
	redirectURI         string
	responseType        string
	scopeQuery          string
	state               string
	nonce               string
	codeChallenge       string
	codeChallengeMethod string
	// prompt (if used)
	// originalParams map[string]string // If needed by sub-functions
}

// parseAndValidateAuthorizeParams extracts and performs basic validation of OIDC parameters.
func (oa *OAuth2API) parseAndValidateAuthorizeParams(c *gin.Context) (*authorizeRequestData, error) {
	data := &authorizeRequestData{
		clientID:            c.Query("client_id"),
		redirectURI:         c.Query("redirect_uri"),
		responseType:        c.Query("response_type"),
		scopeQuery:          c.Query("scope"),
		state:               c.Query("state"),
		nonce:               c.Query("nonce"),
		codeChallenge:       c.Query("code_challenge"),
		codeChallengeMethod: c.Query("code_challenge_method"),
	}

	if data.clientID == "" || data.redirectURI == "" || data.responseType == "" {
		err := domain.NewInvalidRequest("client_id, redirect_uri, and response_type are required")
		oa.sendJSONError(c, http.StatusBadRequest, err)
		return nil, err
	}
	if data.responseType != "code" {
		err := domain.NewInvalidRequest("unsupported response_type, only 'code' is supported")
		oa.sendJSONError(c, http.StatusBadRequest, err)
		return nil, err
	}
	return data, nil
}

// validateClientDetails checks client existence, redirect URI, and scope.
// Returns *domain.OAuth2Error or nil.
func (oa *OAuth2API) validateClientDetails(ctx context.Context, clientID, redirectURI, scopeQuery string) error {
	_, err := oa.clientService.GetClient(ctx, clientID)
	if err != nil {
		log.Warn().Err(err).Str("client_id", clientID).Msg("AuthorizeHandler: Invalid client_id")
		return domain.NewInvalidClient("invalid client_id")
	}
	if err := oa.clientService.ValidateRedirectURI(ctx, clientID, redirectURI); err != nil {
		log.Warn().Err(err).Str("client_id", clientID).Str("redirect_uri", redirectURI).Msg("AuthorizeHandler: Invalid redirect_uri")
		return domain.NewInvalidRequest("invalid redirect_uri")
	}
	if err := oa.clientService.ValidateScope(ctx, clientID, strings.Split(scopeQuery, " ")); err != nil {
		log.Warn().Err(err).Str("client_id", clientID).Str("scope", scopeQuery).Msg("AuthorizeHandler: Invalid scope")
		return domain.NewInvalidScope("invalid scope requested")
	}
	return nil
}

// validatePKCE checks PKCE parameters. OAuth 2.1 mandates PKCE for all clients.
// Returns *domain.OAuth2Error or nil.
func (oa *OAuth2API) validatePKCE(ctx context.Context, clientID, codeChallenge, codeChallengeMethod string) error {
	if codeChallenge == "" {
		log.Warn().Str("client_id", clientID).Msg("AuthorizeHandler: PKCE code_challenge is required per OAuth 2.1")
		return domain.NewPKCERequired()
	}
	if codeChallengeMethod != "" && codeChallengeMethod != "S256" && codeChallengeMethod != "plain" {
		log.Warn().Str("client_id", clientID).Str("method", codeChallengeMethod).Msg("AuthorizeHandler: Invalid code_challenge_method")
		return domain.NewInvalidRequest("invalid code_challenge_method, only S256 is supported")
	}
	return nil
}

// tryHandleWithExistingSession checks for an active user session and, if found,
// generates an auth code and redirects the client. Returns true if handled, and an error if processing failed.
func (oa *OAuth2API) tryHandleWithExistingSession(c *gin.Context, data *authorizeRequestData) (handled bool, err error) {
	ctx := c.Request.Context()
	sessionCookie, cookieErr := c.Cookie(SessionCookieName)
	if cookieErr != nil || sessionCookie == "" {
		return false, nil // No cookie, not handled by this path
	}

	userSession, sessionErr := oa.userSessionStore.GetUserSession(sessionCookie)
	if sessionErr == nil {
		// User is logged in.
		// TODO: Handle 'prompt=login' - if present, must re-authenticate even if session exists. (This would return false from here)

		// Check if client requires consent
		client, clientErr := oa.clientService.GetClient(ctx, data.clientID)
		if clientErr != nil {
			log.Error().Err(clientErr).Str("clientID", data.clientID).Msg("AuthorizeHandler: Failed to get client for consent check")
			oa.sendJSONError(c, http.StatusInternalServerError, domain.NewServerError("failed to retrieve client information"))
			return true, clientErr
		}

		if client.RequireConsent {
			// Create flow state for consent
			flowID := uuid.NewString()
			flowState := domain.LoginFlowState{
				FlowID:              flowID,
				ClientID:            data.clientID,
				RedirectURI:         data.redirectURI,
				Scope:               data.scopeQuery,
				State:               data.state,
				Nonce:               data.nonce,
				CodeChallenge:       data.codeChallenge,
				CodeChallengeMethod: data.codeChallengeMethod,
				UserID:              userSession.UserID,
				UserAuthenticatedAt: time.Now(),
				ExpiresAt:           time.Now().Add(10 * time.Minute),
			}

			if storeErr := oa.flowStore.StoreFlow(flowID, flowState); storeErr != nil {
				log.Error().Err(storeErr).Msg("AuthorizeHandler: Failed to store flow state for consent")
				oa.sendJSONError(c, http.StatusInternalServerError, domain.NewServerError("failed to initiate consent flow"))
				return true, storeErr
			}

			// Set flow ID cookie
			http.SetCookie(c.Writer, &http.Cookie{
				Name:     "sso_oidc_flow_id",
				Value:    flowID,
				Path:     "/",
				MaxAge:   int((10 * time.Minute).Seconds()),
				HttpOnly: true,
				Secure:   c.Request.TLS != nil || strings.EqualFold(c.GetHeader("X-Forwarded-Proto"), "https"),
				SameSite: http.SameSiteLaxMode,
			})

			// Redirect to consent screen
			consentURL := oa.config.NextJSLoginURL + "/consent?flow_id=" + url.QueryEscape(flowID)
			log.Info().Str("userID", userSession.UserID).Str("clientID", data.clientID).Str("consentURL", consentURL).Msg("AuthorizeHandler: User authenticated but consent required, redirecting to consent screen.")
			c.Redirect(http.StatusFound, consentURL)
			return true, nil
		}

		// No consent required, proceed with auth code generation
		log.Info().Str("userID", userSession.UserID).Str("clientID", data.clientID).Msg("AuthorizeHandler: User already authenticated. Proceeding to auth code generation.")
		authCode, errGen := oa.service.GenerateAuthCode(
			ctx,
			data.clientID,
			userSession.UserID,
			data.redirectURI,
			data.scopeQuery,
			data.codeChallenge,
			data.codeChallengeMethod,
			data.nonce,
			userSession.AuthenticatedAt,
		)
		if errGen != nil {
			log.Error().Err(errGen).Msg("AuthorizeHandler: Failed to generate authorization code for authenticated user")
			oa.sendJSONError(c, http.StatusInternalServerError, domain.NewServerError("failed to generate authorization code"))
			return true, errGen // Error occurred, but considered "handled" in terms of flow decision
		}
		oa.redirectToClient(c, data.redirectURI, authCode, data.state)
		return true, nil // Handled successfully
	}

	// If session error is not "not found" or "expired", it's an unexpected error.
	if !goerrors.Is(sessionErr, domain.ErrSessionNotFound) && !goerrors.Is(sessionErr, domain.ErrSessionExpired) {
		log.Warn().Err(sessionErr).Msg("AuthorizeHandler: Error validating existing OP session cookie")
		// Potentially return an error here if this is critical, or clear cookie and proceed.
	}
	// Clear bad/expired cookie and proceed to external login.
	oa.clearUserSessionCookie(c)
	return false, nil // Not handled, proceed to external login
}

// initiateExternalLoginFlow sets up the OIDC flow state and redirects the user to the Next.js UI.
// Returns an error if the process fails and a response has been sent.
func (oa *OAuth2API) initiateExternalLoginFlow(c *gin.Context, data *authorizeRequestData) error {
	if oa.config.NextJSLoginURL == "" {
		log.Error().Msg("AuthorizeHandler: NextJSLoginURL is not configured. Cannot redirect to external UI.")
		err := domain.NewServerError("authentication UI not configured")
		oa.sendJSONError(c, http.StatusInternalServerError, err)
		return err
	}

	flowID := uuid.NewString()
	flowState := domain.LoginFlowState{
		FlowID:              flowID,
		ClientID:            data.clientID,
		RedirectURI:         data.redirectURI,
		Scope:               data.scopeQuery,
		State:               data.state,
		Nonce:               data.nonce,
		CodeChallenge:       data.codeChallenge,
		CodeChallengeMethod: data.codeChallengeMethod,
		ExpiresAt:           time.Now().Add(10 * time.Minute),
		OriginalOIDCParams:  oa.extractOriginalOIDCParams(c), // Extracted from original request
	}

	if err := oa.flowStore.StoreFlow(flowID, flowState); err != nil {
		log.Error().Err(err).Msg("AuthorizeHandler: Failed to store OIDC flow state")
		ssoErr := domain.NewServerError("failed to initiate login flow")
		oa.sendJSONError(c, http.StatusInternalServerError, ssoErr)
		return ssoErr
	}

	http.SetCookie(c.Writer, &http.Cookie{
		Name:     "sso_oidc_flow_id",
		Value:    flowID,
		Path:     "/",
		MaxAge:   int((10 * time.Minute).Seconds()),
		HttpOnly: true,
		Secure:   c.Request.TLS != nil || strings.EqualFold(c.GetHeader("X-Forwarded-Proto"), "https"),
		SameSite: http.SameSiteLaxMode,
	})

	csrfToken := uuid.NewString()
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     CSRFCookieName,
		Value:    csrfToken,
		Path:     "/",
		MaxAge:   int((10 * time.Minute).Seconds()),
		HttpOnly: false,
		Secure:   c.Request.TLS != nil || strings.EqualFold(c.GetHeader("X-Forwarded-Proto"), "https"),
		SameSite: http.SameSiteLaxMode,
	})

	nextJSLoginURLParsed, parseErr := url.Parse(oa.config.NextJSLoginURL)
	if parseErr != nil {
		log.Error().Err(parseErr).Str("url", oa.config.NextJSLoginURL).Msg("AuthorizeHandler: Failed to parse NextJSLoginURL")
		ssoErr := domain.NewServerError("invalid authentication UI configuration")
		oa.sendJSONError(c, http.StatusInternalServerError, ssoErr)
		return ssoErr
	}
	// query := nextJSLoginURLParsed.Query()
	// query.Set("client_id", data.clientID) // Optionally pass client_id for UI context
	// nextJSLoginURLParsed.RawQuery = query.Encode()

	log.Info().Str("flowId_cookie_set", flowID).Str("nextjs_url", nextJSLoginURLParsed.String()).Msg("AuthorizeHandler: Redirecting user to Next.js for authentication.")
	c.Redirect(http.StatusFound, nextJSLoginURLParsed.String())
	return nil
}

// sendJSONError is a helper to return JSON errors consistently.
func (oa *OAuth2API) sendJSONError(c *gin.Context, statusCode int, errDetails *domain.OAuth2Error) {
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
		oa.sendJSONError(c, http.StatusInternalServerError, domain.NewServerError("internal error constructing redirect"))
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
	GrantTypeDeviceCode        GrantType = "urn:ietf:params:oauth:grant-type:device_code"
	GrantTypeTokenExchange     GrantType = "urn:ietf:params:oauth:grant-type:token-exchange"
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
	var cli *domain.Client
	var err error // Keep err scoped within this function initially

	isDeviceCodeGrant := GrantType(grantType) == GrantTypeDeviceCode

	if clientID == "" {
		c.JSON(http.StatusBadRequest, domain.NewInvalidRequest("client_id is required"))
		return
	}

	// Client Authentication:
	if clientSecret != "" {
		cli, err = oa.clientService.ValidateClient(ctx, clientID, clientSecret)
		if err != nil {
			log.Error().Err(err).Msg("Invalid client credentials")
			c.JSON(http.StatusUnauthorized, domain.NewInvalidClient("Invalid client credentials"))
			return
		}
	} else {
		cli, err = oa.clientService.GetClient(ctx, clientID)
		if err != nil {
			log.Error().Err(err).Str("client_id", clientID).Msg("Client not found")
			c.JSON(http.StatusBadRequest, domain.NewInvalidClient("Invalid client_id"))
			return
		}
		// Assuming client.Client has IsConfidential() method. If not, this check needs adjustment.
		// For now, let's assume a helper or direct field access like 'cli.Confidential'.
		// This is a placeholder for actual IsConfidential() check.
		if !isDeviceCodeGrant && cli.IsConfidential {
			log.Error().Str("client_id", clientID).Msg("Client is confidential but no secret provided")
			c.JSON(http.StatusUnauthorized, domain.NewInvalidClient("Client secret required for confidential client"))
			return
		}
	}

	// Validate grant type (check if this client is allowed to use this grant type)
	if err := oa.clientService.ValidateGrantType(ctx, clientID, grantType); err != nil {
		log.Error().Err(err).Msg("Grant type not allowed for this client")
		c.JSON(http.StatusBadRequest, domain.NewUnauthorizedClient("Grant type not allowed for this client"))
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
	case GrantTypeTokenExchange:
		tokenResponse, processErr = oa.handleTokenExchangeGrant(c, cli)
	default:
		c.JSON(http.StatusBadRequest, domain.NewUnsupportedGrantType())
		return
	}

	if processErr != nil {
		if c.Writer.Written() {
			return
		}
		// Try to assert to domain.OAuth2Error first
		if oauthErr, ok := processErr.(*domain.OAuth2Error); ok {
			log.Error().Err(oauthErr).Str("code", oauthErr.Code).Msg("Token generation failed (OAuth2Error)")
			// Assuming OAuth2Error has a field like `HTTPStatusCode` or we map codes to status
			// For now, default to Bad Request for many, but could be Unauthorized for invalid_client etc.
			statusCode := http.StatusBadRequest
			if oauthErr.Code == domain.InvalidClient || oauthErr.Code == domain.UnauthorizedClient {
				statusCode = http.StatusUnauthorized
			}
			c.JSON(statusCode, oauthErr)
			return
		}
		// The check for domain.ErrInvalidRequest or domain.ErrInvalidGrant using goerrors.Is
		// is likely incorrect if these are not actual exported error variables.
		// The *domain.OAuth2Error type assertion above should handle these if processErr is of that type
		// and its .Code field matches domain.InvalidRequest or domain.InvalidGrant.
		// If they are some other kind of error that should map to NewInvalidGrant, that's a different scenario.
		// For now, removing this specific block as it's causing undefined errors.

		log.Error().Err(processErr).Msg("Token generation failed (Non-OAuth2Error)")
		c.JSON(http.StatusInternalServerError, domain.NewServerError("Failed to generate token: "+processErr.Error()))
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
		c.JSON(http.StatusInternalServerError, domain.NewServerError("Internal error during token generation"))
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

// UserInfoHandler handles HTTP requests to retrieve user information per OIDC Core spec.
func (oa *OAuth2API) UserInfoHandler(c *gin.Context) {
	authHeader := c.Request.Header.Get("Authorization")
	if authHeader == "" {
		c.JSON(http.StatusUnauthorized, domain.NewInvalidRequest("missing authorization header"))
		return
	}

	tokenParts := strings.Split(authHeader, " ")
	if len(tokenParts) != 2 || tokenParts[0] != "Bearer" {
		c.JSON(http.StatusUnauthorized, domain.NewInvalidRequest("invalid authorization header format"))
		return
	}
	tokenValue := tokenParts[1]

	ctx := c.Request.Context()

	token, err := oa.tokenService.ValidateAccessToken(ctx, tokenValue)
	if err != nil {
		log.Warn().Err(err).Msg("UserInfoHandler: token validation failed")
		c.JSON(http.StatusUnauthorized, domain.NewInvalidRequest("invalid or expired access token"))
		return
	}

	if !strings.Contains(token.Scope, "openid") {
		c.JSON(http.StatusForbidden, domain.NewInvalidRequest("openid scope required for userinfo endpoint"))
		return
	}

	user, err := oa.userRepo.GetUserByID(ctx, token.UserID)
	if err != nil {
		log.Error().Err(err).Str("userID", token.UserID).Msg("UserInfoHandler: failed to fetch user")
		c.JSON(http.StatusInternalServerError, domain.NewServerError("failed to retrieve user information"))
		return
	}

	userInfo := &sssoapi.UserInfo{
		Sub: user.ID,
	}

	if strings.Contains(token.Scope, "profile") {
		name := user.FirstName + " " + user.LastName
		userInfo.Name = &name
		if user.FirstName != "" {
			userInfo.GivenName = &user.FirstName
		}
		if user.LastName != "" {
			userInfo.FamilyName = &user.LastName
		}
		if len(user.Roles) > 0 {
			userInfo.Roles = user.Roles
		}
	}

	if strings.Contains(token.Scope, "email") {
		if user.Email != "" {
			userInfo.Email = &user.Email
			verified := user.Status == domain.UserStatusActive
			userInfo.EmailVerified = &verified
		}
	}

	c.Header("Cache-Control", "no-store")
	c.Header("Pragma", "no-cache")
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
		c.JSON(http.StatusBadRequest, domain.NewInvalidRequest("token parameter is required"))
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
		c.JSON(http.StatusBadRequest, domain.NewInvalidRequest("client_id parameter is required"))
		return
	}
	// Note: client_secret might be optional for public clients.
	// The service.RevokeToken will ultimately decide based on client's configuration.

	ctx := c.Request.Context()

	err := oa.service.RevokeToken(ctx, token, tokenTypeHint, clientID, clientSecret)
	if err != nil {
		// Check for specific OAuth errors to return appropriate status codes
		if oerr, ok := err.(*domain.OAuth2Error); ok { // Use domain.OAuth2Error
			// Compare with error codes from ssoerrors
			if oerr.Code == domain.InvalidClient || oerr.Code == domain.UnauthorizedClient { // Example comparison
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
		c.JSON(http.StatusInternalServerError, domain.NewServerError("Internal server error")) // Use domain.NewServerError
		return
	}

	// As per RFC 7009, if the client authentication was successful,
	// the server MUST respond with HTTP 200 OK status code, regardless of whether
	// the token was found or is invalid.
	c.Status(http.StatusOK)
}

// LogoutHandler implements OIDC RP-Initiated Logout (RFC 7009 / OIDC Session Management).
// Accepts id_token_hint, post_logout_redirect_uri, and state parameters.
// Invalidates the OP session cookie and redirects to post_logout_redirect_uri if valid.
func (oa *OAuth2API) LogoutHandler(c *gin.Context) {
	idTokenHint := c.Query("id_token_hint")
	if idTokenHint == "" {
		idTokenHint = c.PostForm("id_token_hint")
	}
	postLogoutRedirectURI := c.Query("post_logout_redirect_uri")
	if postLogoutRedirectURI == "" {
		postLogoutRedirectURI = c.PostForm("post_logout_redirect_uri")
	}
	state := c.Query("state")
	if state == "" {
		state = c.PostForm("state")
	}

	ctx := c.Request.Context()

	var clientID string
	if idTokenHint != "" {
		token, err := oa.tokenService.ValidateAccessToken(ctx, idTokenHint)
		if err == nil && token.UserID != "" {
			clientID = token.ClientID
			_ = oa.userSessionStore.DeleteUserSessionsByUserID(token.UserID)
		}
	}

	sessionCookie, cookieErr := c.Cookie(SessionCookieName)
	if cookieErr == nil && sessionCookie != "" {
		userSession, sessionErr := oa.userSessionStore.GetUserSession(sessionCookie)
		if sessionErr == nil && userSession != nil {
			_ = oa.userSessionStore.DeleteUserSession(userSession.SessionID)
		}
		oa.clearUserSessionCookie(c)
	}

	if postLogoutRedirectURI == "" {
		c.JSON(http.StatusOK, gin.H{"message": "logout successful"})
		return
	}

	parsedURI, err := url.Parse(postLogoutRedirectURI)
	if err != nil {
		log.Warn().Err(err).Str("uri", postLogoutRedirectURI).Msg("LogoutHandler: invalid post_logout_redirect_uri")
		c.JSON(http.StatusBadRequest, domain.NewInvalidRequest("invalid post_logout_redirect_uri"))
		return
	}

	if clientID != "" {
		client, err := oa.clientService.GetClient(ctx, clientID)
		if err == nil && client != nil && len(client.PostLogoutURIs) > 0 {
			valid := false
			for _, uri := range client.PostLogoutURIs {
				if uri == postLogoutRedirectURI {
					valid = true
					break
				}
			}
			if !valid {
				log.Warn().Str("uri", postLogoutRedirectURI).Str("clientID", clientID).Msg("LogoutHandler: post_logout_redirect_uri not registered")
				c.JSON(http.StatusBadRequest, domain.NewInvalidRequest("post_logout_redirect_uri not registered for this client"))
				return
			}
		}
	}

	if state != "" {
		q := parsedURI.Query()
		q.Set("state", state)
		parsedURI.RawQuery = q.Encode()
	}

	c.Redirect(http.StatusFound, parsedURI.String())
}

// RegisterClientRequest represents a dynamic client registration request per RFC 7591.
type RegisterClientRequest struct {
	RedirectURIs             []string `json:"redirect_uris" binding:"required"`
	ClientName               string   `json:"client_name"`
	ClientURI                string   `json:"client_uri"`
	LogoURI                  string   `json:"logo_uri"`
	Scope                    string   `json:"scope"`
	GrantTypes               []string `json:"grant_types"`
	ResponseTypes            []string `json:"response_types"`
	TokenEndpointAuth        string   `json:"token_endpoint_auth_method"`
	Contacts                 []string `json:"contacts"`
	PolicyURI                string   `json:"policy_uri"`
	TermsOfServiceURI        string   `json:"tos_uri"`
	JWKSURI                  string   `json:"jwks_uri"`
	SectorIdentifierURI      string   `json:"sector_identifier_uri"`
	SubjectType              string   `json:"subject_type"`
	IDTokenSignedResponseAlg string   `json:"id_token_signed_response_alg"`
	RequireConsent           bool     `json:"require_consent"`
	IsConfidential           bool     `json:"is_confidential"`
}

// RegisterClientResponse represents the response from dynamic client registration.
type RegisterClientResponse struct {
	ClientID              string   `json:"client_id"`
	ClientSecret          string   `json:"client_secret,omitempty"`
	ClientIDIssuedAt      int64    `json:"client_id_issued_at"`
	ClientSecretExpiresAt int64    `json:"client_secret_expires_at"`
	RedirectURIs          []string `json:"redirect_uris"`
	ClientName            string   `json:"client_name,omitempty"`
	ClientURI             string   `json:"client_uri,omitempty"`
	LogoURI               string   `json:"logo_uri,omitempty"`
	Contacts              []string `json:"contacts,omitempty"`
	PolicyURI             string   `json:"policy_uri,omitempty"`
	TermsOfServiceURI     string   `json:"tos_uri,omitempty"`
	JWKSURI               string   `json:"jwks_uri,omitempty"`
	Scope                 string   `json:"scope,omitempty"`
	GrantTypes            []string `json:"grant_types,omitempty"`
	ResponseTypes         []string `json:"response_types,omitempty"`
	TokenEndpointAuth     string   `json:"token_endpoint_auth_method,omitempty"`
	RequireConsent        bool     `json:"require_consent,omitempty"`
}

// RegisterClientHandler implements RFC 7591 Dynamic Client Registration.
func (oa *OAuth2API) RegisterClientHandler(c *gin.Context) {
	var req RegisterClientRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, domain.NewInvalidRequest("Invalid registration request: "+err.Error()))
		return
	}

	if len(req.RedirectURIs) == 0 {
		c.JSON(http.StatusBadRequest, domain.NewInvalidRequest("redirect_uris is required"))
		return
	}

	for _, uri := range req.RedirectURIs {
		parsed, err := url.Parse(uri)
		if err != nil {
			c.JSON(http.StatusBadRequest, domain.NewInvalidRequest("invalid redirect_uri: "+uri))
			return
		}
		host := parsed.Hostname()
		isLocalhost := host == "localhost" || host == "127.0.0.1" || host == "::1"
		if parsed.Scheme != "https" && !isLocalhost {
			c.JSON(http.StatusBadRequest, domain.NewInvalidRequest("redirect_uri must use HTTPS (except localhost)"))
			return
		}
	}

	validGrantTypes := map[string]bool{
		"authorization_code": true,
		"implicit":           true,
		"refresh_token":      true,
		"client_credentials": true,
		"password":           true,
	}
	for _, gt := range req.GrantTypes {
		if !validGrantTypes[gt] {
			c.JSON(http.StatusBadRequest, domain.NewInvalidRequest("invalid grant_type: "+gt))
			return
		}
	}

	ctx := c.Request.Context()

	clientID := uuid.NewString()
	clientSecret := ""
	if req.IsConfidential || req.TokenEndpointAuth == "client_secret_basic" || req.TokenEndpointAuth == "client_secret_post" {
		secretBytes := make([]byte, 32)
		if _, err := rand.Read(secretBytes); err != nil {
			c.JSON(http.StatusInternalServerError, domain.NewServerError("Failed to generate client secret"))
			return
		}
		clientSecret = base64.RawURLEncoding.EncodeToString(secretBytes)
	}

	grantTypes := req.GrantTypes
	if len(grantTypes) == 0 {
		grantTypes = []string{"authorization_code"}
	}

	newClient := &domain.Client{
		ID:                clientID,
		Secret:            clientSecret,
		Name:              req.ClientName,
		RedirectURIs:      req.RedirectURIs,
		AllowedScopes:     strings.Split(req.Scope, " "),
		AllowedGrantTypes: grantTypes,
		TokenEndpointAuth: req.TokenEndpointAuth,
		Contacts:          req.Contacts,
		LogoURI:           req.LogoURI,
		PolicyURI:         req.PolicyURI,
		TermsURI:          req.TermsOfServiceURI,
		JWKSUri:           req.JWKSURI,
		RequireConsent:    req.RequireConsent,
		IsConfidential:    clientSecret != "",
		IsActive:          true,
		Type:              domain.ClientTypePublic,
		CreatedAt:         time.Now(),
		UpdatedAt:         time.Now(),
	}

	if clientSecret != "" {
		newClient.Type = domain.ClientTypeConfidential
	}

	if err := oa.clientService.CreateClient(ctx, newClient); err != nil {
		log.Error().Err(err).Msg("Failed to create client via dynamic registration")
		c.JSON(http.StatusInternalServerError, domain.NewServerError("Failed to register client"))
		return
	}

	resp := RegisterClientResponse{
		ClientID:          clientID,
		ClientSecret:      clientSecret,
		ClientIDIssuedAt:  time.Now().Unix(),
		RedirectURIs:      req.RedirectURIs,
		ClientName:        req.ClientName,
		ClientURI:         req.ClientURI,
		LogoURI:           req.LogoURI,
		Contacts:          req.Contacts,
		PolicyURI:         req.PolicyURI,
		TermsOfServiceURI: req.TermsOfServiceURI,
		JWKSURI:           req.JWKSURI,
		Scope:             req.Scope,
		GrantTypes:        grantTypes,
		ResponseTypes:     req.ResponseTypes,
		TokenEndpointAuth: req.TokenEndpointAuth,
		RequireConsent:    req.RequireConsent,
	}
	if clientSecret != "" {
		resp.ClientSecretExpiresAt = 0
	}

	c.Header("Cache-Control", "no-store")
	c.Header("Pragma", "no-cache")
	c.JSON(http.StatusCreated, resp)
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
	scheme := c.Request.URL.Scheme
	if scheme == "" {
		scheme = "http"
	}

	baseURL := scheme + "://" + c.Request.Host
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

func (oa *OAuth2API) DirectGrantHandler(c *gin.Context) {
	clientID := c.PostForm("client_id")
	clientSecret := c.PostForm("client_secret")
	username := c.PostForm("username")
	password := c.PostForm("password")
	scope := c.PostForm("scope")

	if clientID == "" || clientSecret == "" || username == "" || password == "" {
		c.JSON(http.StatusBadRequest, domain.NewInvalidRequest("Missing required parameters"))
		return
	}

	ctx := c.Request.Context()

	token, err := oa.service.DirectGrant(ctx, clientID, clientSecret, username, password, scope)
	if err != nil {
		log.Error().Err(err).Msg("direct grant failed")
		c.JSON(http.StatusBadRequest, domain.NewInvalidGrant("Invalid credentials"))
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
		c.JSON(http.StatusBadRequest, domain.NewInvalidRequest("Missing client credentials"))
		return
	}

	ctx := c.Request.Context()

	token, err := oa.service.ClientCredentials(ctx, clientID, clientSecret, scope)
	if err != nil {
		log.Error().Err(err).Msg("client credentials grant failed")
		c.JSON(http.StatusBadRequest, domain.NewInvalidClient("Invalid client credentials"))
		return
	}

	c.JSON(http.StatusOK, token)
}

func (oa *OAuth2API) handleAuthorizationCodeGrant(c *gin.Context, cli *domain.Client) (*sssoapi.TokenResponse, error) {
	code := c.PostForm("code")
	redirectURI := c.PostForm("redirect_uri")
	codeVerifier := c.PostForm("code_verifier")

	ctx := c.Request.Context()

	// OAuth 2.1 mandates PKCE for all clients
	if codeVerifier == "" {
		return nil, domain.NewPKCERequired()
	}
	if err := oa.pkceService.ValidateCodeVerifier(ctx, code, codeVerifier); err != nil {
		return nil, domain.NewInvalidPKCE(err.Error())
	}

	return oa.service.ExchangeAuthorizationCode(ctx, code, cli.ID, cli.Secret, redirectURI)
}

func (oa *OAuth2API) handlePasswordGrant(c *gin.Context, cli *domain.Client) (*sssoapi.TokenResponse, error) {
	log.Warn().Msg("DEPRECATED: password grant type is deprecated per OAuth 2.1. Migrate to authorization code flow with PKCE.")

	username := c.PostForm("username")
	password := c.PostForm("password")
	clientID := c.PostForm("client_id")
	scope := c.PostForm("scope")

	if username == "" || password == "" || clientID == "" {
		return nil, domain.NewInvalidRequest("missing required parameters. " +
			"Required parameters: username, password, client_id")
	}

	ctx := c.Request.Context()

	return oa.service.PasswordGrant(ctx, username, password, scope, cli)
}

func (oa *OAuth2API) handleClientCredentialsGrant(c *gin.Context, cli *domain.Client) (*sssoapi.TokenResponse, error) {
	scope := c.PostForm("scope")

	ctx := c.Request.Context()

	return oa.service.ClientCredentials(ctx, cli.ID, cli.Secret, scope)
}

func (oa *OAuth2API) handleTokenExchangeGrant(c *gin.Context, cli *domain.Client) (*sssoapi.TokenResponse, error) {
	subjectToken := c.PostForm("subject_token")
	subjectTokenType := c.PostForm("subject_token_type")
	requestedTokenType := c.PostForm("requested_token_type")
	resource := c.PostForm("resource")
	scope := c.PostForm("scope")

	if subjectToken == "" {
		return nil, domain.NewInvalidRequest("subject_token is required")
	}
	if subjectTokenType == "" {
		subjectTokenType = "urn:ietf:params:oauth:token-type:access_token"
	}
	if requestedTokenType == "" {
		requestedTokenType = "urn:ietf:params:oauth:token-type:access_token"
	}

	ctx := c.Request.Context()

	return oa.service.TokenExchange(ctx, subjectToken, subjectTokenType, requestedTokenType, resource, scope, cli.ID)
}

func (oa *OAuth2API) handleRefreshTokenGrant(c *gin.Context, cli *domain.Client) (*sssoapi.TokenResponse, error) {
	refreshToken := c.PostForm("refresh_token")
	if refreshToken == "" {
		return nil, domain.NewInvalidRequest("refresh_token is required")
	}

	ctx := c.Request.Context()

	tokenResponse, err := oa.service.RefreshToken(ctx, refreshToken, cli.ID)
	if err == nil && tokenResponse != nil {
		metrics.TokensRefreshedTotal.Inc()
	}
	return tokenResponse, err
}

// handleDeviceCodeGrant is called by TokenHandler for device_code grant type
func (oa *OAuth2API) handleDeviceCodeGrant(c *gin.Context, cli *domain.Client) (*sssoapi.TokenResponse, error) {
	deviceCode := c.PostForm("device_code")
	requestClientID := c.PostForm("client_id") // client_id from form body

	if deviceCode == "" {
		return nil, domain.NewInvalidRequest("device_code is required")
	}
	// client_id is also required in the body for device_code grant (RFC 8628 Sec 3.4)
	if requestClientID == "" {
		return nil, domain.NewInvalidRequest("client_id is required in request body for device_code grant")
	}
	// Ensure the client_id in the body matches the authenticated client
	// cli.ID comes from client authentication (if confidential) or from client_id in body (if public)
	if cli != nil && requestClientID != cli.ID {
		// This case implies client_id in body doesn't match client_id used for auth (if any)
		// or if a public client sent client_id in body that doesn't match the one resolved by GetClient earlier
		return nil, domain.NewInvalidGrant("client_id in request body does not match client_id used for request")
	}

	ctx := c.Request.Context()
	// Pass cli.ID as the clientID for IssueTokenForDeviceFlow, as this is the validated/authenticated client.
	tokenResponse, err := oa.service.IssueTokenForDeviceFlow(ctx, deviceCode, cli.ID)
	if err != nil {
		// Handle specific device flow errors by writing to response and returning nil error
		// so TokenHandler knows response is handled.
		if goerrors.Is(err, domain.ErrAuthorizationPending) {
			c.Header("Cache-Control", "no-store")
			c.Header("Pragma", "no-cache")
			c.JSON(http.StatusBadRequest, &domain.OAuth2Error{
				Code:        "authorization_pending",
				Description: err.Error(),
			})
			return nil, nil // Signal to TokenHandler that response is sent
		}
		if goerrors.Is(err, domain.ErrSlowDown) {
			c.Header("Cache-Control", "no-store")
			c.Header("Pragma", "no-cache")
			c.JSON(http.StatusBadRequest, &domain.OAuth2Error{
				Code:        "slow_down",
				Description: err.Error(),
			})
			return nil, nil
		}
		if goerrors.Is(err, domain.ErrDeviceFlowTokenExpired) {
			c.Header("Cache-Control", "no-store")
			c.Header("Pragma", "no-cache")
			c.JSON(http.StatusBadRequest, &domain.OAuth2Error{
				Code:        "expired_token",
				Description: err.Error(),
			})
			return nil, nil
		}
		if goerrors.Is(err, domain.ErrDeviceFlowAccessDenied) {
			c.Header("Cache-Control", "no-store")
			c.Header("Pragma", "no-cache")
			c.JSON(http.StatusBadRequest, &domain.OAuth2Error{
				Code:        "access_denied",
				Description: err.Error(),
			})
			return nil, nil
		}
		if oauthErr, ok := err.(*domain.OAuth2Error); ok && oauthErr.Code == domain.InvalidClient {
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
		c.JSON(http.StatusUnauthorized, domain.NewInvalidClient("client authentication required"))
		return
	}

	token := c.PostForm("token")
	if token == "" {
		c.JSON(http.StatusBadRequest, domain.NewInvalidRequest("token parameter is required"))
		return
	}

	tokenType := c.PostForm("token_type_hint")

	ctx := c.Request.Context()

	introspection, err := oa.service.IntrospectToken(ctx, token, tokenType, clientID, clientSecret)
	if err != nil {
		log.Error().Err(err).Msg("token introspection failed")
		// According to RFC 7662, we should still return 200 OK with active=false
		c.JSON(http.StatusOK, &domain.TokenIntrospection{Active: false})
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
		if goerrors.Is(err, domain.ErrFlowNotFound) { // Changed errors.Is to goerrors.Is
			c.JSON(http.StatusNotFound, gin.H{"error": "invalid_flow", "error_description": "Flow ID not found."})
			return
		}
		if goerrors.Is(err, domain.ErrFlowExpired) { // Changed errors.Is to goerrors.Is
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
		"client_id":       flowState.ClientID,
		"client_name":     client.Name, // Example: send client name
		"scope":           flowState.Scope,
		"original_params": flowState.OriginalOIDCParams, // Send original params if UI needs them
		// Add any other details the Next.js UI might need to display context to the user.
	})
}

// AuthenticateUserRequest defines the expected JSON body for the /api/oidc/authenticate endpoint.
type AuthenticateUserRequest struct {
	FlowID    string `json:"flow_id" binding:"required"`
	Email     string `json:"email" binding:"required,email"`
	Password  string `json:"password" binding:"required"`
	CSRFToken string `json:"csrf_token" binding:"required"`
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

	csrfCookie, csrfErr := c.Cookie(CSRFCookieName)
	if csrfErr != nil || csrfCookie == "" || csrfCookie != req.CSRFToken {
		c.JSON(http.StatusForbidden, gin.H{"error": "invalid_csrf", "error_description": "CSRF token mismatch or missing."})
		return
	}

	flowState, err := oa.flowStore.GetFlow(req.FlowID)
	if err != nil {
		if goerrors.Is(err, domain.ErrFlowNotFound) || goerrors.Is(err, domain.ErrFlowExpired) { // Use goerrors.Is
			desc := "Flow ID not found or expired."
			if goerrors.Is(err, domain.ErrFlowExpired) { // Use goerrors.Is
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

	// Client information was already retrieved and validated earlier in the function

	// Authentication successful, create OIDC Provider session for the user.
	sessionID := uuid.NewString()
	opSessionExpiry := time.Now().Add(24 * time.Hour) // Example: 24-hour session for the OP
	userSession := &domain.UserSession{
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
		Path:     "/",                  // Adjust path if necessary
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

	// Check if consent is required for this client
	client, err := oa.clientService.GetClient(ctx, flowState.ClientID)
	if err != nil {
		log.Error().Err(err).Str("clientID", flowState.ClientID).Msg("Failed to get client for consent check")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error", "error_description": "Could not retrieve client information."})
		return
	}

	if client.RequireConsent {
		// Redirect to consent screen instead of generating auth code
		consentURL := oa.config.NextJSLoginURL + "/consent?flow_id=" + url.QueryEscape(req.FlowID)
		log.Info().Str("flowId", req.FlowID).Str("userID", user.ID).Str("consentURL", consentURL).Msg("User authenticated, redirecting to consent screen.")
		c.Redirect(http.StatusFound, consentURL)
		return
	}

	// No consent required, proceed with authorization code generation
	authCode, err := oa.service.GenerateAuthCode(
		ctx,
		flowState.ClientID,
		user.ID, // Pass the authenticated UserID
		flowState.RedirectURI,
		flowState.Scope,
		flowState.CodeChallenge,       // Pass stored code challenge
		flowState.CodeChallengeMethod, // Pass stored code challenge method
		flowState.Nonce,
		flowState.UserAuthenticatedAt,
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

// ConsentRequest defines the expected JSON body for the /api/oidc/consent endpoint.
type ConsentRequest struct {
	FlowID    string `json:"flow_id" binding:"required"`
	Approved  bool   `json:"approved"`
	CSRFToken string `json:"csrf_token" binding:"required"`
}

// ConsentHandler handles the user's consent submission from the Next.js UI.
func (oa *OAuth2API) ConsentHandler(c *gin.Context) {
	var req ConsentRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, domain.NewInvalidRequest("Invalid request payload: "+err.Error()))
		return
	}

	ctx := c.Request.Context()

	csrfCookie, csrfErr := c.Cookie(CSRFCookieName)
	if csrfErr != nil || csrfCookie == "" || csrfCookie != req.CSRFToken {
		c.JSON(http.StatusForbidden, domain.NewInvalidRequest("CSRF token mismatch or missing."))
		return
	}

	flowState, err := oa.flowStore.GetFlow(req.FlowID)
	if err != nil {
		if goerrors.Is(err, domain.ErrFlowNotFound) || goerrors.Is(err, domain.ErrFlowExpired) {
			c.JSON(http.StatusForbidden, gin.H{"error": "invalid_flow", "error_description": "Flow ID not found or expired."})
			return
		}
		log.Error().Err(err).Str("flowId", req.FlowID).Msg("Error retrieving flow state during consent")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error", "error_description": "Could not retrieve flow details."})
		return
	}

	if flowState.UserID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_flow", "error_description": "User not authenticated for this flow."})
		return
	}

	_ = ctx

	if !req.Approved {
		_ = oa.flowStore.DeleteFlow(req.FlowID)

		redirectURL := flowState.RedirectURI
		params := url.Values{}
		params.Set("error", "access_denied")
		params.Set("error_description", "The resource owner denied the request")
		if flowState.State != "" {
			params.Set("state", flowState.State)
		}
		if strings.Contains(redirectURL, "?") {
			redirectURL += "&" + params.Encode()
		} else {
			redirectURL += "?" + params.Encode()
		}
		c.Redirect(http.StatusFound, redirectURL)
		return
	}

	authCode, err := oa.service.GenerateAuthCode(
		ctx,
		flowState.ClientID,
		flowState.UserID,
		flowState.RedirectURI,
		flowState.Scope,
		flowState.CodeChallenge,
		flowState.CodeChallengeMethod,
		flowState.Nonce,
		flowState.UserAuthenticatedAt,
	)
	if err != nil {
		log.Error().Err(err).Str("flowId", req.FlowID).Msg("Failed to generate authorization code after consent")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error", "error_description": "Could not complete authorization."})
		return
	}

	_ = oa.flowStore.DeleteFlow(req.FlowID)

	redirectURL := flowState.RedirectURI
	params := url.Values{}
	params.Set("code", authCode)
	if flowState.State != "" {
		params.Set("state", flowState.State)
	}
	if strings.Contains(redirectURL, "?") {
		redirectURL += "&" + params.Encode()
	} else {
		redirectURL += "?" + params.Encode()
	}

	log.Info().Str("flowId", req.FlowID).Str("userID", flowState.UserID).Msg("Consent granted, redirecting to client with auth code.")
	c.Redirect(http.StatusFound, redirectURL)
}
