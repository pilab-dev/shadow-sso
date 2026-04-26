package webauth

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"net/http"

	"github.com/gin-gonic/gin"
)

// SocialLoginHandler handles GET /login/:provider — looks up the identity
// provider configuration, generates a CSRF state nonce (optionally encoding
// the OIDC flow_id for callback recovery), stores the nonce in a short-lived
// cookie, obtains the provider's OAuth authorization URL from the federation
// service, and redirects the user to the external identity provider.
//
// Supported providers include OIDC (Google, Apple) and plain OAuth (GitHub).
func (wa *WebAuth) SocialLoginHandler(c *gin.Context) {
	providerName := c.Param("provider")
	flowID := GetFlowIDFromCookie(c.Request)

	// 1. Validate the login flow if a flow_id was provided.
	if flowID != "" {
		_, err := wa.flowStore.GetFlow(c.Request.Context(), flowID)
		if err != nil {
			c.HTML(http.StatusBadRequest, "error.html", gin.H{
				"PageTitle": "Error",
				"Message":   "Invalid or expired login request",
			})
			return
		}
	}

	// 2. Look up the identity provider configuration by name.
	provider, err := wa.idpRepo.GetIdPByName(c.Request.Context(), providerName)
	if err != nil || provider == nil || !provider.IsEnabled {
		c.HTML(http.StatusNotFound, "error.html", gin.H{
			"PageTitle": "Error",
			"Message":   "Unknown identity provider",
		})
		return
	}

	// 3. Generate a random state nonce for CSRF protection.
	stateBytes := make([]byte, 32)
	if _, err := rand.Read(stateBytes); err != nil {
		c.HTML(http.StatusInternalServerError, "error.html", gin.H{
			"PageTitle": "Error",
			"Message":   "Internal error",
		})
		return
	}
	state := hex.EncodeToString(stateBytes)

	// 4. Encode flow_id in the state parameter for callback recovery.
	//    Format: base64url(flow_id + "." + random_nonce)
	//    If no flow_id is present, the raw nonce is used as-is.
	encodedState := state
	if flowID != "" {
		encodedState = base64.RawURLEncoding.EncodeToString(
			[]byte(flowID + "." + state),
		)
	}

	// 5. Store the raw nonce in a short-lived cookie so the callback handler
	//    can validate the state parameter returned by the provider.
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     "sso_oauth_state",
		Value:    state,
		Path:     "/",
		MaxAge:   600, // 10 minutes
		HttpOnly: true,
		Secure:   IsSecureRequest(c.Request),
		SameSite: http.SameSiteLaxMode,
	})

	// 6. Obtain the provider's OAuth authorization URL. The federation service
	//    handles provider-specific endpoint construction (Google, GitHub, Apple).
	authURL, err := wa.federationService.GetAuthorizationURL(
		c.Request.Context(), providerName, encodedState,
	)
	if err != nil {
		c.HTML(http.StatusInternalServerError, "error.html", gin.H{
			"PageTitle": "Error",
			"Message":   "Failed to initiate login",
		})
		return
	}

	// 7. Redirect the user to the external identity provider.
	c.Redirect(http.StatusFound, authURL)
}


