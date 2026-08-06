package webauth

import (
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/pilab-dev/shadow-sso/internal/auth/totp"
	"github.com/pilab-dev/shadow-sso/internal/ssosession"
	"github.com/rs/zerolog/log"
)

// MFASubmitHandler processes POST /mfa. It validates the TOTP code submitted
// from mfa.html against the user recorded on the flow state during login, then
// completes the flow:
//   - real OIDC flows (ClientID set) redirect to /oauth2/authorize?flow_id=<id>,
//     exactly like the non-MFA completion path in LoginSubmitHandler;
//   - flow-less (synthetic, ClientID-less) logins redirect to the signed
//     sso_return_to destination captured when the synthetic flow began, falling
//     back to "/" when the cookie is absent or invalid.
func (wa *WebAuth) MFASubmitHandler(c *gin.Context) {
	if !validateCSRFTokenForm(c) {
		c.HTML(http.StatusBadRequest, "error.html", gin.H{
			"PageTitle": "Error",
			"Message":   "Invalid or expired login request. Please try again.",
		})
		return
	}

	flowID := c.PostForm("flow_id")
	if flowID == "" {
		c.HTML(http.StatusBadRequest, "error.html", gin.H{
			"PageTitle": "Error",
			"Message":   "Invalid or expired login request. Please try again.",
		})
		return
	}

	ctx := c.Request.Context()

	flowState, err := wa.flowStore.GetFlow(ctx, flowID)
	if err != nil {
		log.Warn().Err(err).Str("flow_id", flowID).Msg("mfa: flow not found")
		c.HTML(http.StatusBadRequest, "error.html", gin.H{
			"PageTitle": "Error",
			"Message":   "Invalid or expired login request. Please try again.",
		})
		return
	}
	if time.Now().After(flowState.ExpiresAt) {
		log.Warn().Str("flow_id", flowID).Msg("mfa: flow expired")
		_ = wa.flowStore.DeleteFlow(ctx, flowID)
		c.HTML(http.StatusBadRequest, "error.html", gin.H{
			"PageTitle": "Error",
			"Message":   "Invalid or expired login request. Please try again.",
		})
		return
	}

	userID := flowState.UserID
	if userID == "" {
		log.Warn().Str("flow_id", flowID).Msg("mfa: no authenticated user in flow")
		c.HTML(http.StatusBadRequest, "error.html", gin.H{
			"PageTitle": "Error",
			"Message":   "Invalid or expired login request. Please try again.",
		})
		return
	}

	user, err := wa.userRepo.GetUserByID(ctx, userID)
	if err != nil {
		log.Warn().Err(err).Str("flow_id", flowID).Str("user_id", userID).Msg("mfa: user not found")
		c.HTML(http.StatusBadRequest, "error.html", gin.H{
			"PageTitle": "Error",
			"Message":   "Invalid or expired login request. Please try again.",
		})
		return
	}

	otp := c.PostForm("otp")
	valid, err := totp.ValidateTOTPCode(user.TwoFactorSecret, otp)
	if err != nil {
		log.Error().Err(err).Str("flow_id", flowID).Msg("mfa: TOTP validation error")
		c.HTML(http.StatusInternalServerError, "error.html", gin.H{
			"PageTitle": "Error",
			"Message":   "Failed to verify the code. Please try again.",
		})
		return
	}
	if !valid {
		log.Warn().Str("flow_id", flowID).Msg("mfa: invalid verification code")
		csrfToken, tErr := generateCSRFToken()
		if tErr != nil {
			log.Error().Err(tErr).Msg("mfa: failed to generate CSRF token")
			c.HTML(http.StatusInternalServerError, "error.html", gin.H{
				"PageTitle": "Error",
				"Message":   "Internal error. Please try again.",
			})
			return
		}
		isSecure := IsSecureRequest(c.Request)
		setCSRFCookie(c.Writer, csrfToken, 10*time.Minute, isSecure)
		c.HTML(http.StatusOK, "mfa.html", gin.H{
			"PageTitle": "Two-Factor Authentication",
			"FlowID":    flowID,
			"CSRFToken": csrfToken,
			"Error":     "Invalid verification code. Please try again.",
			"BrandName": wa.config.BrandOrganizationName,
		})
		return
	}

	displayName := user.Email
	if user.FirstName != "" || user.LastName != "" {
		displayName = fmt.Sprintf("%s %s", user.FirstName, user.LastName)
	}
	isSecure := IsSecureRequest(c.Request)
	session := &ssosession.Session{
		SessionID: ssosession.NewID(),
		Accounts: []ssosession.Account{{
			UserID:   user.ID,
			Email:    user.Email,
			Name:     displayName,
			LastUsed: time.Now(),
		}},
	}
	if err := SetSSOSessionCookie(c.Writer, session, isSecure, wa.ssoCookieSecret); err != nil {
		log.Error().Err(err).Msg("mfa: failed to set SSO session cookie")
		c.HTML(http.StatusInternalServerError, "error.html", gin.H{
			"PageTitle": "Error",
			"Message":   "Failed to create session. Please try again.",
		})
		return
	}

	flowState.UserID = user.ID
	if flowState.UserAuthenticatedAt.IsZero() {
		flowState.UserAuthenticatedAt = time.Now()
	}
	if err := wa.flowStore.UpdateFlow(ctx, flowID, flowState); err != nil {
		log.Error().Err(err).Str("flow_id", flowID).Msg("mfa: failed to update flow state")
	}

	if flowState.ClientID == "" {
		// Flow-less login (no OIDC client): complete by redirecting to the
		// signed return_to destination captured when the synthetic flow began.
		// The cookie is cleared on use; fall back to "/" when absent or invalid.
		rt := readReturnToCookie(c.Request, wa.ssoCookieSecret)
		clearReturnToCookie(c.Writer, isSecure)
		if rt != "" && validReturnTo(rt) {
			c.Redirect(http.StatusFound, rt)
			return
		}
		c.Redirect(http.StatusFound, "/")
		return
	}
	c.Redirect(http.StatusFound, "/oauth2/authorize?flow_id="+url.QueryEscape(flowID))
}
