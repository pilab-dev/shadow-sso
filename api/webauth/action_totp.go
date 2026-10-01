package webauth

import (
	"encoding/base64"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/pilab-dev/shadow-sso/domain"
	"github.com/pilab-dev/shadow-sso/internal/auth/totp"
	"github.com/rs/zerolog/log"
)

// configureTOTPAction implements CONFIGURE_TOTP: enrol an authenticator app.
// The secret is persisted on the user as soon as it is shown (method TOTP, not yet
// enabled) so an error re-render keeps the QR code stable.
type configureTOTPAction struct{}

func (configureTOTPAction) Render(c *gin.Context, wa *WebAuth, flowID string, user *domain.User, errMsg string) {
	ctx := c.Request.Context()
	if user.TwoFactorSecret == "" || user.TwoFactorMethod != "TOTP" || user.IsTwoFactorEnabled {
		key, _, err := totp.GenerateTOTPSecret(wa.config.BrandOrganizationName, user.Email)
		if err != nil {
			log.Error().Err(err).Msg("totp setup: generate secret failed")
			wa.renderInternalError(c, "Could not start authenticator setup. Please try again.")
			return
		}
		user.TwoFactorSecret = key.Secret()
		user.TwoFactorMethod = "TOTP"
		if err := wa.userRepo.UpdateUser(ctx, user); err != nil {
			log.Error().Err(err).Msg("totp setup: persist secret failed")
			wa.renderInternalError(c, "Could not start authenticator setup. Please try again.")
			return
		}
	}

	uri := totpProvisioningURI(wa.config.BrandOrganizationName, user.Email, user.TwoFactorSecret)
	png, err := totp.GenerateTOTPQRCodeBytes(uri)
	if err != nil {
		log.Error().Err(err).Msg("totp setup: QR generation failed")
		wa.renderInternalError(c, "Could not render the QR code. Please try again.")
		return
	}

	csrfToken, err := generateCSRFToken()
	if err != nil {
		wa.renderInternalError(c, "Internal error. Please try again.")
		return
	}
	setCSRFCookie(c.Writer, csrfToken, 10*time.Minute, IsSecureRequest(c.Request))
	status := http.StatusOK
	if errMsg != "" {
		status = http.StatusUnprocessableEntity
	}
	c.HTML(status, "totp_setup.html", gin.H{
		"PageTitle": "Set up authenticator",
		"FlowID":    flowID,
		"CSRFToken": csrfToken,
		"Error":     errMsg,
		"BrandName": wa.config.BrandOrganizationName,
		// The data URI is built from server-generated PNG bytes, so it is safe to mark as a URL.
		"QRCode": template.URL("data:image/png;base64," + base64.StdEncoding.EncodeToString(png)),
		"Secret": user.TwoFactorSecret,
	})
}

func (configureTOTPAction) Submit(c *gin.Context, wa *WebAuth, user *domain.User) (actionResult, error) {
	if user.TwoFactorSecret == "" || user.TwoFactorMethod != "TOTP" || user.IsTwoFactorEnabled {
		return actionResult{Err: "Authenticator setup was reset. Scan the new QR code and try again."}, nil
	}
	valid, err := totp.ValidateTOTPCode(user.TwoFactorSecret, c.PostForm("otp"))
	if err != nil {
		return actionResult{}, err
	}
	if !valid {
		return actionResult{Err: "Invalid verification code. Please try again."}, nil
	}

	plain, hashed, err := totp.GenerateRecoveryCodes(totp.DefaultNumRecoveryCodes, totp.DefaultRecoveryCodeLength)
	if err != nil {
		return actionResult{}, err
	}
	user.IsTwoFactorEnabled = true
	user.TwoFactorRecoveryCodes = hashed
	user.RemoveRequiredAction(domain.RequiredActionConfigureTOTP)
	if err := wa.userRepo.UpdateUser(c.Request.Context(), user); err != nil {
		return actionResult{}, err
	}

	// Recovery codes are shown exactly once; "Continue" posts continue=1 to resume the login.
	csrfToken, err := generateCSRFToken()
	if err != nil {
		return actionResult{}, err
	}
	setCSRFCookie(c.Writer, csrfToken, 10*time.Minute, IsSecureRequest(c.Request))
	c.HTML(http.StatusOK, "recovery_codes.html", gin.H{
		"PageTitle": "Save your recovery codes",
		"FlowID":    c.PostForm("flow_id"),
		"CSRFToken": csrfToken,
		"BrandName": wa.config.BrandOrganizationName,
		"Codes":     plain,
	})
	return actionResult{Rendered: true}, nil
}

// totpProvisioningURI builds the otpauth:// URI authenticator apps import.
func totpProvisioningURI(issuer, account, secret string) string {
	label := url.PathEscape(issuer + ":" + account)
	q := url.Values{}
	q.Set("secret", secret)
	q.Set("issuer", issuer)
	q.Set("algorithm", "SHA1")
	q.Set("digits", "6")
	q.Set("period", "30")
	return fmt.Sprintf("otpauth://totp/%s?%s", label, q.Encode())
}
