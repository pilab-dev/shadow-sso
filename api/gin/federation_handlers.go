package sssogin

import (
	"fmt"
	"net/http"

	// For error checking in callback
	"connectrpc.com/connect"
	"github.com/gin-gonic/gin"
	ssov1 "github.com/pilab-dev/shadow-sso/gen/proto/sso/v1"
	"github.com/pilab-dev/shadow-sso/gen/proto/sso/v1/ssov1connect"
	"github.com/rs/zerolog/log"
)

const (
	federationStateCookieName = "sso_federation_state"
	// TODO: Make cookie secure, HttpOnly, SameSite, and Path configurable
	cookieMaxAge = 300 // 5 minutes for state cookie
)

// FederationAPI provides HTTP handlers for federation flows.
type FederationAPI struct {
	federationClient ssov1connect.FederationServiceClient
	// uiRedirectBaseURL string // Base URL to redirect to for UI feedback (e.g. "https://myapp.com/auth")
}

// NewFederationAPI creates a new FederationAPI.
func NewFederationAPI(federationClient ssov1connect.FederationServiceClient /*, uiRedirectBaseURL string*/) *FederationAPI {
	return &FederationAPI{
		federationClient: federationClient,
		// uiRedirectBaseURL: uiRedirectBaseURL,
	}
}

// RegisterFederationRoutes registers the federation HTTP routes.
func (fapi *FederationAPI) RegisterFederationRoutes(rg *gin.RouterGroup) {
	fedGroup := rg.Group("/federation")
	{
		fedGroup.GET("/:provider/login", fapi.InitiateLoginHandler)
		// The callback URL must match exactly what's configured with the IdP.
		// Using a single callback endpoint and passing provider in path is common.
		fedGroup.GET("/callback/:provider", fapi.CallbackHandler)
		// Apple sends a POST to the callback
		fedGroup.POST("/callback/:provider", fapi.CallbackHandler)
	}
}

// InitiateLoginHandler initiates the federated login flow.
// It calls the gRPC FederationService.InitiateFederatedLogin, gets the auth URL and state,
// stores the state in a cookie, and redirects the user.
func (fapi *FederationAPI) InitiateLoginHandler(c *gin.Context) {
	providerName := c.Param("provider")
	if providerName == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "provider_name_missing", "message": "Provider name is missing in path."})
		return
	}

	req := connect.NewRequest(&ssov1.InitiateFederatedLoginRequest{
		ProviderName: providerName,
	})

	resp, err := fapi.federationClient.InitiateFederatedLogin(c.Request.Context(), req)
	if err != nil {
		log.Error().Err(err).Str("provider", providerName).Msg("Failed to initiate federated login via gRPC")
		// Check connect error code
		if connectErr, ok := err.(*connect.Error); ok {
			if connectErr.Code() == connect.CodeNotFound {
				c.JSON(http.StatusNotFound, gin.H{"error": "provider_not_found", "message": fmt.Sprintf("Provider '%s' not found or not configured.", providerName)})
				return
			}
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "initiation_failed", "message": "Could not start federated login."})
		return
	}

	// Store state in a secure, HttpOnly cookie
	// TODO: Use proper configuration for cookie domain, secure flag, etc.
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     federationStateCookieName,
		Value:    resp.Msg.State,
		Path:     "/", // Adjust path if necessary, e.g., to the callback path's parent
		MaxAge:   cookieMaxAge,
		Secure:   c.Request.TLS != nil, // Set Secure flag if served over HTTPS
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})

	c.Redirect(http.StatusFound, resp.Msg.AuthorizationUrl)
}

// CallbackHandler handles the redirect from the external identity provider.
// It retrieves code and state, verifies state against cookie, then calls gRPC FederationService.HandleFederatedCallback.
func (fapi *FederationAPI) CallbackHandler(c *gin.Context) {
	providerName := c.Param("provider")
	if providerName == "" {
		// This should not happen if routes are set up correctly
		c.JSON(http.StatusBadRequest, gin.H{"error": "provider_name_missing_in_callback", "message": "Provider name is missing in callback path."})
		return
	}

	// Retrieve state from cookie
	stateCookie, err := c.Cookie(federationStateCookieName)
	if err != nil {
		log.Warn().Err(err).Msg("State cookie not found during callback")
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing_state_cookie", "message": "Authentication session expired or invalid."})
		return
	}
	// Clear the state cookie once read
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     federationStateCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1, // Expire immediately
		Secure:   c.Request.TLS != nil,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})

	var code, queryState, idToken, userFormParam string
	_ = userFormParam

	// Apple sends data via POST with application/x-www-form-urlencoded
	if c.Request.Method == http.MethodPost && providerName == "apple" {
		if err := c.Request.ParseForm(); err != nil {
			log.Warn().Err(err).Str("provider", providerName).Msg("Failed to parse form POST for Apple callback")
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_apple_callback", "message": "Could not parse Apple callback data."})

			return
		}

		code = c.Request.PostFormValue("code")
		queryState = c.Request.PostFormValue("state")
		idToken = c.Request.PostFormValue("id_token")   // Apple might send ID token here
		userFormParam = c.Request.PostFormValue("user") // Apple sends user JSON string here on first auth if name/email scopes requested
	} else { // GET for most other providers
		code = c.Query("code")
		queryState = c.Query("state")

		// Handle OAuth errors passed in query params
		oauthError := c.Query("error")
		if oauthError != "" {
			oauthErrorDesc := c.Query("error_description")

			log.Warn().Str("provider", providerName).
				Str("error", oauthError).
				Str("desc", oauthErrorDesc).
				Msg("OAuth error in callback from provider")

			// TODO: Redirect to a UI page that displays this error nicely
			c.JSON(http.StatusBadRequest, gin.H{"error": "provider_error", "message": fmt.Sprintf("Error from %s: %s (%s)", providerName, oauthError, oauthErrorDesc)})

			return
		}
	}

	if queryState == "" {
		log.Warn().
			Str("provider", providerName).
			Msg("State parameter missing in callback query")

		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "missing_state_param",
			"message": "State parameter missing in callback.",
		})

		return
	}

	if code == "" && !(providerName == "apple" && idToken != "") { // Apple might not send code if it sends id_token directly for some flows (not typical for 'code' flow)
		log.Warn().
			Str("provider", providerName).
			Msg("Authorization code missing in callback query")

		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "missing_code",
			"message": "Authorization code missing in callback.",
		})

		return
	}

	// Verify state (CSRF protection)
	if queryState != stateCookie {
		log.Warn().
			Str("provider", providerName).
			Str("queryState", queryState).
			Str("cookieState", stateCookie).
			Msg("State mismatch in callback")

		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "state_mismatch",
			"message": "Invalid session state. Please try logging in again.",
		})

		return
	}

	grpcReq := &ssov1.HandleFederatedCallbackRequest{
		ProviderName: providerName,
		State:        queryState, // Validated state
		Code:         code,
	}
	// if providerName == "apple" {
	// grpcReq.IdToken = idToken // Pass along if received, gRPC service can use it
	// grpcReq.User = userFormParam
	// }

	resp, err := fapi.federationClient.HandleFederatedCallback(c.Request.Context(), connect.NewRequest(grpcReq))
	if err != nil {
		log.Error().
			Err(err).
			Str("provider", providerName).
			Msg("gRPC HandleFederatedCallback failed")

		// TODO: More granular error handling based on connect.Code and resp.Msg.Status
		// For now, a generic error. The UI should handle different statuses from response message.
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "callback_processing_failed",
			"message": "Failed to process login with provider.",
		})

		return
	}

	// Based on resp.Msg.Status, take action
	switch resp.Msg.Status {
	case ssov1.HandleFederatedCallbackResponse_LOGIN_SUCCESSFUL, ssov1.HandleFederatedCallbackResponse_ACCOUNT_LINKED_LOGIN:
		// Login successful. Set session cookie(s) with tokens.
		// This part is similar to how a normal login would set cookies.
		// TODO: Standardize session cookie setting (e.g., in a shared auth middleware/util).
		// For now, assume access_token is primary for session or use a dedicated session cookie.
		// This example just returns tokens in body; client SPA would store them.
		// In a server-rendered app, you'd set secure session cookies.
		log.Info().
			Str("provider", providerName).
			Str("userID", resp.Msg.UserInfo.Id).
			Msg("Federated login/link successful")

		c.JSON(http.StatusOK, gin.H{
			"status":        resp.Msg.Status.String(),
			"message":       resp.Msg.Message,
			"access_token":  resp.Msg.AccessToken,
			"refresh_token": resp.Msg.RefreshToken,
			"token_type":    resp.Msg.TokenType,
			"expires_in":    resp.Msg.ExpiresIn,
			"user_info":     resp.Msg.UserInfo,
		})
		// Example redirect to a dashboard:
		// http.Redirect(c.Writer, c.Request, fapi.uiRedirectBaseURL+"/dashboard", http.StatusFound)

	case ssov1.HandleFederatedCallbackResponse_MERGE_REQUIRED_EMAIL_EXISTS:
		log.Info().Str("provider", providerName).Str("email", resp.Msg.ProviderEmail).Msg("Federated login requires account merge.")
		// Redirect to a UI page that handles merge, passing continuation_token
		// mergeURL := fmt.Sprintf("%s/merge-account?token=%s&provider=%s", fapi.uiRedirectBaseURL, resp.Msg.ContinuationToken, providerName)
		// http.Redirect(c.Writer, c.Request, mergeURL, http.StatusFound)
		c.JSON(http.StatusOK, gin.H{ // Or a specific HTTP status like 202 Accepted
			"status":             resp.Msg.Status.String(),
			"message":            resp.Msg.Message,
			"provider_name":      resp.Msg.ProviderName,
			"provider_email":     resp.Msg.ProviderEmail,
			"continuation_token": resp.Msg.ContinuationToken,
		})

	case ssov1.HandleFederatedCallbackResponse_NEW_USER_REGISTRATION_REQUIRED:
		log.Info().Str("provider", providerName).Str("email", resp.Msg.ProviderEmail).Msg("Federated login requires new user registration completion.")
		// Redirect to a UI page for completing registration, passing continuation_token
		// registerURL := fmt.Sprintf("%s/complete-registration?token=%s&provider=%s", fapi.uiRedirectBaseURL, resp.Msg.ContinuationToken, providerName)
		// http.Redirect(c.Writer, c.Request, registerURL, http.StatusFound)
		c.JSON(http.StatusOK, gin.H{ // Or a specific HTTP status
			"status":             resp.Msg.Status.String(),
			"message":            resp.Msg.Message,
			"provider_name":      resp.Msg.ProviderName,
			"provider_email":     resp.Msg.ProviderEmail,
			"continuation_token": resp.Msg.ContinuationToken,
		})

	default:
		log.Error().Str("provider", providerName).Str("status", resp.Msg.Status.String()).Msg("Unhandled status from HandleFederatedCallback")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "unhandled_callback_status", "message": resp.Msg.Message})
	}
}
