package webauth

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/pilab-dev/shadow-sso/domain"
	"github.com/rs/zerolog/log"
)

// fedcmClosePath is the flow-less completion URL for the FedCM active-mode
// login dialog. It closes the dialog after the user signs in.
const fedcmClosePath = "/fedcm/close"

// startFedCMLogin starts a dedicated FedCM active-mode login flow. It uses its
// own flow cookie so a normal OIDC authorize flow in another window is not
// disturbed. The flow completes at /fedcm/close, which calls
// IdentityProvider.close() to close the browser's FedCM login dialog.
func (wa *WebAuth) startFedCMLogin(c *gin.Context) {
	ctx := c.Request.Context()
	flowID := uuid.NewString()
	flowState := &domain.LoginFlowState{
		FlowID:    flowID,
		ExpiresAt: time.Now().Add(syntheticFlowLifetime),
	}
	if err := wa.flowStore.StoreFlow(ctx, flowID, *flowState); err != nil {
		log.Error().Err(err).Msg("fedcm login: failed to store synthetic flow")
		c.HTML(http.StatusInternalServerError, "error.html", gin.H{
			"PageTitle": "Error",
			"Message":   "Internal error. Please try again.",
		})
		return
	}

	isSecure := IsSecureRequest(c.Request)
	setFedCMFlowCookies(c.Writer, flowID, isSecure)
	setReturnToCookie(c.Writer, fedcmClosePath, isSecure, wa.ssoCookieSecret)

	providers, err := wa.idpRepo.ListIdPs(ctx, true)
	if err != nil {
		log.Error().Err(err).Msg("fedcm login: failed to load identity providers")
		providers = nil
	}

	wa.renderLoginStart(c, flowID, providers, "")
}

// FedCMClosePageHandler completes the FedCM active-mode login flow. The browser
// opened /login?fedcm=1 in a FedCM dialog window; after login the dialog must be
// closed with IdentityProvider.close().
func (wa *WebAuth) FedCMClosePageHandler(c *gin.Context) {
	isSecure := IsSecureRequest(c.Request)
	ClearFedCMFlowCookies(c.Writer, isSecure)
	c.Header("Cache-Control", "no-store")
	c.HTML(http.StatusOK, "fedcm_close.html", gin.H{
		"PageTitle": "Signed in",
	})
}
