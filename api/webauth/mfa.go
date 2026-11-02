package webauth

import (
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/pilab-dev/shadow-sso/domain"
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

	flowState.FlowID = flowID
	userID := flowState.UserID
	if userID == "" {
		log.Warn().Str("flow_id", flowID).Msg("mfa: no authenticated user in flow")
		c.HTML(http.StatusBadRequest, "error.html", gin.H{
			"PageTitle": "Error",
			"Message":   "Invalid or expired login request. Please try again.",
		})
		return
	}

	// Brute-force protection for the second factor. The password step resets
	// its own limiter on success, so MFA attempts need a separate counter.
	rateLimitKey := "mfa:" + c.ClientIP() + ":" + userID
	if !wa.rateLimiter.Allow(rateLimitKey) {
		log.Warn().Str("flow_id", flowID).Str("user_id", userID).Str("ip", c.ClientIP()).Msg("mfa: rate limited")
		wa.renderMFAPage(c, flowID, "Too many attempts. Please try again later.")
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
		wa.rateLimiter.RecordFailure(rateLimitKey)
		log.Warn().Str("flow_id", flowID).Msg("mfa: invalid verification code")
		wa.renderMFAPage(c, flowID, "Invalid verification code. Please try again.")
		return
	}
	wa.rateLimiter.Reset(rateLimitKey)

	wa.completeMFA(c, flowState, user)
}

// completeMFA finishes a login that has passed its second factor: it creates
// the OP session, stores the signed SSO session cookie and hands off to the
// OIDC completion path. It is shared by the TOTP prompt and the enrollment
// flow.
func (wa *WebAuth) completeMFA(c *gin.Context, flowState *domain.LoginFlowState, user *domain.User) {
	ctx := c.Request.Context()

	opSession, err := wa.establishOPSession(c, user.ID)
	if err != nil {
		log.Error().Err(err).Str("user_id", user.ID).Msg("mfa: failed to establish OP session")
		c.HTML(http.StatusInternalServerError, "error.html", gin.H{
			"PageTitle": "Error",
			"Message":   "Failed to create session. Please try again.",
		})
		return
	}

	displayName := user.Email
	if user.FirstName != "" || user.LastName != "" {
		displayName = fmt.Sprintf("%s %s", user.FirstName, user.LastName)
	}
	isSecure := IsSecureRequest(c.Request)
	session := wa.mergeLoginSession(c.Request, ssosession.Account{
		UserID:      user.ID,
		Email:       user.Email,
		Name:        displayName,
		OPSessionID: opSession.SessionID,
		LastUsed:    time.Now(),
	})
	if err := SetSSOSessionCookie(c.Writer, session, isSecure, wa.ssoCookieSecret); err != nil {
		log.Error().Err(err).Msg("mfa: failed to set SSO session cookie")
		c.HTML(http.StatusInternalServerError, "error.html", gin.H{
			"PageTitle": "Error",
			"Message":   "Failed to create session. Please try again.",
		})
		return
	}

	flowState.UserID = user.ID
	flowState.MFAEnrollmentVerified = false
	if flowState.UserAuthenticatedAt.IsZero() {
		flowState.UserAuthenticatedAt = time.Now()
	}
	if err := wa.flowStore.UpdateFlow(ctx, flowState.FlowID, flowState); err != nil {
		log.Error().Err(err).Str("flow_id", flowState.FlowID).Msg("mfa: failed to update flow state")
	}

	wa.completeLogin(c, flowState, isSecure)
}

// renderMFAPage re-renders the MFA form with a fresh CSRF token and an
// optional error message. It is used for invalid codes and rate limiting.
func (wa *WebAuth) renderMFAPage(c *gin.Context, flowID, errMsg string) {
	csrfToken, err := generateCSRFToken()
	if err != nil {
		log.Error().Err(err).Msg("mfa: failed to generate CSRF token")
		c.HTML(http.StatusInternalServerError, "error.html", gin.H{
			"PageTitle": "Error",
			"Message":   "Internal error. Please try again.",
		})
		return
	}

	setCSRFCookie(c.Writer, csrfToken, 10*time.Minute, IsSecureRequest(c.Request))
	c.HTML(http.StatusOK, "mfa.html", gin.H{
		"PageTitle": "Two-Factor Authentication",
		"FlowID":    flowID,
		"CSRFToken": csrfToken,
		"Error":     errMsg,
		"BrandName": wa.config.BrandOrganizationName,
	})
}
