package webauth

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/pilab-dev/shadow-sso/internal/auth/totp"
	"github.com/rs/zerolog/log"
)

// renderMFAPage renders mfa.html, tailoring the copy to the user's configured
// MFA method (EMAIL shows the masked destination address, everything else
// shows the generic authenticator-app copy).
func (wa *WebAuth) renderMFAPage(c *gin.Context, flowID, method, email, errMsg string) {
	wa.renderMFAPageWithInfo(c, flowID, method, email, errMsg, "")
}

// renderMFAPageWithInfo is renderMFAPage plus a non-error, informational
// message (e.g. "a new code was sent") shown alongside/instead of Error.
func (wa *WebAuth) renderMFAPageWithInfo(c *gin.Context, flowID, method, email, errMsg, infoMsg string) {
	csrfToken, err := generateCSRFToken()
	if err != nil {
		log.Error().Err(err).Msg("mfa: failed to generate CSRF token")
		c.HTML(http.StatusInternalServerError, "error.html", gin.H{
			"PageTitle": "Error",
			"Message":   "Internal error. Please try again.",
		})
		return
	}
	isSecure := IsSecureRequest(c.Request)
	setCSRFCookie(c.Writer, csrfToken, 10*time.Minute, isSecure)

	c.HTML(http.StatusOK, "mfa.html", gin.H{
		"PageTitle":   "Two-Factor Authentication",
		"FlowID":      flowID,
		"CSRFToken":   csrfToken,
		"Error":       errMsg,
		"Info":        infoMsg,
		"BrandName":   wa.config.BrandOrganizationName,
		"IsEmail":     method == "EMAIL",
		"MaskedEmail": maskEmail(email),
	})
}

// maskEmail obscures the local part of an email address for display, e.g.
// "jane.doe@example.com" -> "ja***@example.com".
func maskEmail(email string) string {
	at := -1
	for i, r := range email {
		if r == '@' {
			at = i
			break
		}
	}
	if at <= 0 {
		return email
	}
	local := email[:at]
	domain := email[at:]
	if len(local) <= 2 {
		return local[:1] + "***" + domain
	}
	return local[:2] + "***" + domain
}

// MFASubmitHandler processes POST /mfa. It validates the code submitted from
// mfa.html (TOTP from an authenticator app, or an emailed OTP) against the
// user recorded on the flow state during login, then completes the flow:
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

	var valid bool
	if user.TwoFactorMethod == "EMAIL" {
		if wa.mfaService == nil {
			log.Error().Str("flow_id", flowID).Msg("mfa: email MFA required but MFA service is not configured")
			c.HTML(http.StatusInternalServerError, "error.html", gin.H{
				"PageTitle": "Error",
				"Message":   "Email verification is not available. Please contact support.",
			})
			return
		}
		valid, err = wa.mfaService.VerifyMFAChallenge(ctx, userID, otp, 0)
	} else {
		// TOTP (the default when TwoFactorMethod is unset, for backward
		// compatibility with accounts enrolled before the method field existed).
		valid, err = totp.ValidateTOTPCode(user.TwoFactorSecret, otp)
	}
	if err != nil {
		log.Error().Err(err).Str("flow_id", flowID).Msg("mfa: code validation error")
		c.HTML(http.StatusInternalServerError, "error.html", gin.H{
			"PageTitle": "Error",
			"Message":   "Failed to verify the code. Please try again.",
		})
		return
	}
	if !valid {
		log.Warn().Str("flow_id", flowID).Msg("mfa: invalid verification code")
		wa.renderMFAPage(c, flowID, user.TwoFactorMethod, user.Email, "Invalid verification code. Please try again.")
		return
	}

	// Second factor verified: clear the pending marker and run the shared completion
	// point (required actions, SSO cookie, consent, authorization).
	flowState.Pending = ""
	wa.finishLogin(c, ctx, flowID, flowState, user)
}

// MFAResendSubmitHandler processes POST /mfa/resend. It re-sends the email
// OTP for the user recorded on the flow state and re-renders mfa.html with a
// confirmation (or error) message. It is a no-op for non-EMAIL MFA methods
// (authenticator-app codes are generated client-side, nothing to resend).
func (wa *WebAuth) MFAResendSubmitHandler(c *gin.Context) {
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
	if err != nil || time.Now().After(flowState.ExpiresAt) || flowState.UserID == "" {
		log.Warn().Err(err).Str("flow_id", flowID).Msg("mfa: resend on invalid or expired flow")
		c.HTML(http.StatusBadRequest, "error.html", gin.H{
			"PageTitle": "Error",
			"Message":   "Invalid or expired login request. Please try again.",
		})
		return
	}

	user, err := wa.userRepo.GetUserByID(ctx, flowState.UserID)
	if err != nil {
		log.Warn().Err(err).Str("flow_id", flowID).Msg("mfa: resend user not found")
		c.HTML(http.StatusBadRequest, "error.html", gin.H{
			"PageTitle": "Error",
			"Message":   "Invalid or expired login request. Please try again.",
		})
		return
	}

	if user.TwoFactorMethod != "EMAIL" || wa.mfaService == nil {
		wa.renderMFAPage(c, flowID, user.TwoFactorMethod, user.Email, "")
		return
	}

	if _, _, _, err := wa.mfaService.SendMFAChallenge(ctx, user.ID); err != nil {
		log.Warn().Err(err).Str("flow_id", flowID).Msg("mfa: failed to resend email code")
		wa.renderMFAPageWithInfo(c, flowID, user.TwoFactorMethod, user.Email, "Couldn't resend the code. Please wait a moment and try again.", "")
		return
	}

	wa.renderMFAPageWithInfo(c, flowID, user.TwoFactorMethod, user.Email, "", "A new code was sent to your email.")
}
