package webauth

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/pilab-dev/shadow-sso/domain"
	"github.com/pilab-dev/shadow-sso/internal/auth/totp"
	"github.com/rs/zerolog/log"
	"rsc.io/qr"
)

// MFAEnrollPageHandler serves the forced TOTP enrollment page shown when MFA
// is required for an account that has no usable factor yet.
func (wa *WebAuth) MFAEnrollPageHandler(c *gin.Context) {
	flowID := c.Query("flow_id")
	if flowID == "" {
		flowID = GetFlowIDFromCookie(c.Request)
	}
	flowState, ok := wa.loadMFACeremonyFlow(c, flowID)
	if !ok {
		return
	}

	ctx := c.Request.Context()
	user, err := wa.userRepo.GetUserByID(ctx, flowState.UserID)
	if err != nil {
		log.Warn().Err(err).Str("flow_id", flowID).Msg("mfa-enroll: user not found")
		c.HTML(http.StatusBadRequest, "error.html", gin.H{
			"PageTitle": "Error",
			"Message":   "Invalid or expired login request. Please try again.",
		})
		return
	}

	if !wa.mfaEnforced(ctx, user) {
		c.HTML(http.StatusForbidden, "error.html", gin.H{
			"PageTitle": "Error",
			"Message":   "Second-factor enrollment is not required for this account.",
		})
		return
	}
	if hasUsableTOTP(user) {
		c.Redirect(http.StatusFound, "/mfa?flow_id="+url.QueryEscape(flowID))
		return
	}
	if wa.hasUnverifiableActiveFactor(user) {
		c.HTML(http.StatusForbidden, "error.html", gin.H{
			"PageTitle": "Second factor unavailable",
			"Message":   "This account already has another second factor that this page cannot verify. Contact your administrator to reset it.",
		})
		return
	}

	// Start (or restart) the enrollment ceremony. The secret is stored on the
	// user but 2FA stays disabled until a code is verified.
	otpKey, otpAuthURI, err := totp.GenerateTOTPSecret(wa.config.BrandOrganizationName, user.Email)
	if err != nil {
		log.Error().Err(err).Str("user_id", user.ID).Msg("mfa-enroll: failed to generate TOTP secret")
		c.HTML(http.StatusInternalServerError, "error.html", gin.H{
			"PageTitle": "Error",
			"Message":   "Could not start enrollment. Please try again.",
		})
		return
	}
	user.TwoFactorSecret = otpKey.Secret()
	user.TwoFactorMethod = "TOTP"
	user.IsTwoFactorEnabled = false
	user.UpdatedAt = time.Now()
	if err := wa.userRepo.UpdateUser(ctx, user); err != nil {
		log.Error().Err(err).Str("user_id", user.ID).Msg("mfa-enroll: failed to store pending TOTP secret")
		c.HTML(http.StatusInternalServerError, "error.html", gin.H{
			"PageTitle": "Error",
			"Message":   "Could not start enrollment. Please try again.",
		})
		return
	}

	wa.renderMFAEnrollPage(c, flowState, user, otpAuthURI, "")
}

// MFAEnrollSubmitHandler verifies the first TOTP code and enables 2FA.
func (wa *WebAuth) MFAEnrollSubmitHandler(c *gin.Context) {
	if !validateCSRFTokenForm(c) {
		c.HTML(http.StatusBadRequest, "error.html", gin.H{
			"PageTitle": "Error",
			"Message":   "Invalid or expired login request. Please try again.",
		})
		return
	}

	flowID := c.PostForm("flow_id")
	flowState, ok := wa.loadMFACeremonyFlow(c, flowID)
	if !ok {
		return
	}

	ctx := c.Request.Context()
	user, err := wa.userRepo.GetUserByID(ctx, flowState.UserID)
	if err != nil {
		log.Warn().Err(err).Str("flow_id", flowID).Msg("mfa-enroll: user not found on submit")
		c.HTML(http.StatusBadRequest, "error.html", gin.H{
			"PageTitle": "Error",
			"Message":   "Invalid or expired login request. Please try again.",
		})
		return
	}

	if !wa.mfaEnforced(ctx, user) {
		c.HTML(http.StatusForbidden, "error.html", gin.H{
			"PageTitle": "Error",
			"Message":   "Second-factor enrollment is not required for this account.",
		})
		return
	}
	if hasUsableTOTP(user) {
		c.Redirect(http.StatusFound, "/mfa?flow_id="+url.QueryEscape(flowID))
		return
	}
	if wa.hasUnverifiableActiveFactor(user) {
		c.HTML(http.StatusForbidden, "error.html", gin.H{
			"PageTitle": "Second factor unavailable",
			"Message":   "This account already has another second factor that this page cannot verify. Contact your administrator to reset it.",
		})
		return
	}
	if user.TwoFactorSecret == "" || user.TwoFactorMethod != "TOTP" {
		c.Redirect(http.StatusFound, "/mfa/enroll?flow_id="+url.QueryEscape(flowID))
		return
	}

	rateLimitKey := "mfa-enroll:" + c.ClientIP() + ":" + user.ID
	if !wa.rateLimiter.Allow(rateLimitKey) {
		wa.renderMFAEnrollPage(c, flowState, user, "", "Too many attempts. Please try again later.")
		return
	}

	code := strings.TrimSpace(c.PostForm("code"))
	valid, err := totp.ValidateTOTPCode(user.TwoFactorSecret, code)
	if err != nil || !valid {
		wa.rateLimiter.RecordFailure(rateLimitKey)
		wa.renderMFAEnrollPage(c, flowState, user, buildOTPAuthURI(wa.config.BrandOrganizationName, user.Email, user.TwoFactorSecret), "Invalid verification code. Please try again.")
		return
	}
	wa.rateLimiter.Reset(rateLimitKey)

	plaintextCodes, hashedCodes, err := totp.GenerateRecoveryCodes(totp.DefaultNumRecoveryCodes, totp.DefaultRecoveryCodeLength)
	if err != nil {
		log.Error().Err(err).Str("user_id", user.ID).Msg("mfa-enroll: failed to generate recovery codes")
		c.HTML(http.StatusInternalServerError, "error.html", gin.H{
			"PageTitle": "Error",
			"Message":   "Could not complete enrollment. Please try again.",
		})
		return
	}

	user.IsTwoFactorEnabled = true
	user.TwoFactorMethod = "TOTP"
	user.TwoFactorRecoveryCodes = hashedCodes
	user.UpdatedAt = time.Now()
	if err := wa.userRepo.UpdateUser(ctx, user); err != nil {
		log.Error().Err(err).Str("user_id", user.ID).Msg("mfa-enroll: failed to enable 2FA")
		c.HTML(http.StatusInternalServerError, "error.html", gin.H{
			"PageTitle": "Error",
			"Message":   "Could not complete enrollment. Please try again.",
		})
		return
	}

	flowState.MFAEnrollmentVerified = true
	if err := wa.flowStore.UpdateFlow(ctx, flowID, flowState); err != nil {
		log.Error().Err(err).Str("flow_id", flowID).Msg("mfa-enroll: failed to record verified enrollment")
		c.HTML(http.StatusInternalServerError, "error.html", gin.H{
			"PageTitle": "Error",
			"Message":   "Could not complete enrollment. Please try again.",
		})
		return
	}

	csrfToken, err := generateCSRFToken()
	if err != nil {
		c.HTML(http.StatusInternalServerError, "error.html", gin.H{"PageTitle": "Error", "Message": "Internal error. Please try again."})
		return
	}
	setCSRFCookie(c.Writer, csrfToken, 10*time.Minute, IsSecureRequest(c.Request))
	c.HTML(http.StatusOK, "mfa_recovery.html", gin.H{
		"PageTitle":     "Save your recovery codes",
		"FlowID":        flowID,
		"CSRFToken":     csrfToken,
		"RecoveryCodes": plaintextCodes,
		"BrandName":     wa.config.BrandOrganizationName,
	})
}

// MFAEnrollCompleteHandler finishes the login after the enrollment ceremony
// was verified in this flow.
func (wa *WebAuth) MFAEnrollCompleteHandler(c *gin.Context) {
	if !validateCSRFTokenForm(c) {
		c.HTML(http.StatusBadRequest, "error.html", gin.H{
			"PageTitle": "Error",
			"Message":   "Invalid or expired login request. Please try again.",
		})
		return
	}

	flowID := c.PostForm("flow_id")
	flowState, ok := wa.loadMFACeremonyFlow(c, flowID)
	if !ok {
		return
	}
	if !flowState.MFAEnrollmentVerified {
		log.Warn().Str("flow_id", flowID).Msg("mfa-enroll: completion attempted without verified enrollment")
		c.HTML(http.StatusForbidden, "error.html", gin.H{
			"PageTitle": "Error",
			"Message":   "Enrollment has not been verified. Please start again.",
		})
		return
	}

	ctx := c.Request.Context()
	user, err := wa.userRepo.GetUserByID(ctx, flowState.UserID)
	if err != nil || !hasUsableTOTP(user) {
		c.HTML(http.StatusBadRequest, "error.html", gin.H{
			"PageTitle": "Error",
			"Message":   "Enrollment is incomplete. Please start again.",
		})
		return
	}

	wa.completeMFA(c, flowState, user)
}

// loadMFACeremonyFlow loads and validates a flow that has already passed the
// password step. It renders the error page and returns false on failure.
func (wa *WebAuth) loadMFACeremonyFlow(c *gin.Context, flowID string) (*domain.LoginFlowState, bool) {
	if flowID == "" {
		c.HTML(http.StatusBadRequest, "error.html", gin.H{
			"PageTitle": "Error",
			"Message":   "Invalid or expired login request. Please try again.",
		})
		return nil, false
	}

	ctx := c.Request.Context()
	flowState, err := wa.flowStore.GetFlow(ctx, flowID)
	if err != nil {
		log.Warn().Err(err).Str("flow_id", flowID).Msg("mfa-enroll: flow not found")
		c.HTML(http.StatusBadRequest, "error.html", gin.H{
			"PageTitle": "Error",
			"Message":   "Invalid or expired login request. Please try again.",
		})
		return nil, false
	}
	if time.Now().After(flowState.ExpiresAt) {
		_ = wa.flowStore.DeleteFlow(ctx, flowID)
		c.HTML(http.StatusBadRequest, "error.html", gin.H{
			"PageTitle": "Error",
			"Message":   "Login request has expired. Please try again.",
		})
		return nil, false
	}
	if flowState.UserID == "" {
		c.HTML(http.StatusBadRequest, "error.html", gin.H{
			"PageTitle": "Error",
			"Message":   "Invalid or expired login request. Please try again.",
		})
		return nil, false
	}
	flowState.FlowID = flowID
	return flowState, true
}

// renderMFAEnrollPage renders the QR + manual secret form. The QR is rebuilt
// from the stored secret so a failed code entry does not invalidate what the
// user already scanned.
func (wa *WebAuth) renderMFAEnrollPage(c *gin.Context, flowState *domain.LoginFlowState, user *domain.User, otpAuthURI, errMsg string) {
	if otpAuthURI == "" {
		otpAuthURI = buildOTPAuthURI(wa.config.BrandOrganizationName, user.Email, user.TwoFactorSecret)
	}
	qrDataURI, err := qrPNGDataURI(otpAuthURI)
	if err != nil {
		log.Error().Err(err).Msg("mfa-enroll: failed to render QR code")
		qrDataURI = ""
	}

	csrfToken, err := generateCSRFToken()
	if err != nil {
		log.Error().Err(err).Msg("mfa-enroll: failed to generate CSRF token")
		c.HTML(http.StatusInternalServerError, "error.html", gin.H{"PageTitle": "Error", "Message": "Internal error. Please try again."})
		return
	}
	setCSRFCookie(c.Writer, csrfToken, 10*time.Minute, IsSecureRequest(c.Request))

	c.HTML(http.StatusOK, "mfa_enroll.html", gin.H{
		"PageTitle":  "Set up two-factor authentication",
		"FlowID":     flowState.FlowID,
		"CSRFToken":  csrfToken,
		"Secret":     user.TwoFactorSecret,
		"QRDataURI":  qrDataURI,
		"Email":      user.Email,
		"BrandName":  wa.config.BrandOrganizationName,
		"BrandColor": wa.config.BrandPrimaryColor,
		"Error":      errMsg,
	})
}

// buildOTPAuthURI builds the otpauth:// URI for an existing secret. It mirrors
// the layout pquerna/otp generates, without rotating the secret.
func buildOTPAuthURI(issuer, account, secret string) string {
	label := url.PathEscape(issuer + ":" + account)
	q := url.Values{}
	q.Set("secret", secret)
	q.Set("issuer", issuer)
	q.Set("algorithm", "SHA1")
	q.Set("digits", "6")
	q.Set("period", "30")
	return "otpauth://totp/" + label + "?" + q.Encode()
}

// qrPNGDataURI renders a QR code as an inline PNG data URI. The login pages
// use a CSP of img-src 'self' data:, so no external asset is needed.
func qrPNGDataURI(content string) (string, error) {
	code, err := qr.Encode(content, qr.M)
	if err != nil {
		return "", fmt.Errorf("encode qr: %w", err)
	}
	return "data:image/png;base64," + base64.StdEncoding.EncodeToString(code.PNG()), nil
}
