package webauth

import (
	"encoding/base64"
	"fmt"
	"html/template"
	"net/url"

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
	qr, secret, ok := wa.prepareTOTP(c, user)
	if !ok {
		return
	}
	wa.renderPage(c, "totp_setup.html", "Set up authenticator", gin.H{
		"FlowID": flowID,
		"Error":  errMsg,
		"QRCode": qr,
		"Secret": secret,
		"Action": "/required-action",
	})
}

func (configureTOTPAction) Submit(c *gin.Context, wa *WebAuth, user *domain.User) (actionResult, error) {
	codes, errMsg, err := wa.enableTOTP(c, user)
	if err != nil || errMsg != "" {
		return actionResult{Err: errMsg}, err
	}
	user.RemoveRequiredAction(domain.RequiredActionConfigureTOTP)
	if err := wa.userRepo.UpdateUser(c.Request.Context(), user); err != nil {
		return actionResult{}, err
	}
	// Recovery codes are shown exactly once; "Continue" posts continue=1 to resume the login.
	wa.renderPage(c, "recovery_codes.html", "Save your recovery codes", gin.H{
		"FlowID": c.PostForm("flow_id"),
		"Codes":  codes,
		"Action": "/required-action",
	})
	return actionResult{Rendered: true}, nil
}

// prepareTOTP makes sure user has a pending (not yet enabled) TOTP secret and returns the QR
// code data URI and the manual-entry key. On failure it writes an error page and returns ok=false.
func (wa *WebAuth) prepareTOTP(c *gin.Context, user *domain.User) (qr template.URL, secret string, ok bool) {
	if user.TwoFactorSecret == "" || user.TwoFactorMethod != "TOTP" || user.IsTwoFactorEnabled {
		key, _, err := totp.GenerateTOTPSecret(wa.config.BrandOrganizationName, user.Email)
		if err != nil {
			log.Error().Err(err).Msg("totp setup: generate secret failed")
			wa.renderInternalError(c, "Could not start authenticator setup. Please try again.")
			return "", "", false
		}
		user.TwoFactorSecret = key.Secret()
		user.TwoFactorMethod = "TOTP"
		if err := wa.userRepo.UpdateUser(c.Request.Context(), user); err != nil {
			log.Error().Err(err).Msg("totp setup: persist secret failed")
			wa.renderInternalError(c, "Could not start authenticator setup. Please try again.")
			return "", "", false
		}
	}
	png, err := totp.GenerateTOTPQRCodeBytes(totpProvisioningURI(wa.config.BrandOrganizationName, user.Email, user.TwoFactorSecret))
	if err != nil {
		log.Error().Err(err).Msg("totp setup: QR generation failed")
		wa.renderInternalError(c, "Could not render the QR code. Please try again.")
		return "", "", false
	}
	// The data URI is built from server-generated PNG bytes, so it is safe to mark as a URL.
	return template.URL("data:image/png;base64," + base64.StdEncoding.EncodeToString(png)), user.TwoFactorSecret, true
}

// enableTOTP verifies the submitted code against the pending secret and, when valid, switches TOTP
// on in memory (the caller persists) and returns the plaintext recovery codes. errMsg is a
// user-facing validation message; err is an internal failure.
func (wa *WebAuth) enableTOTP(c *gin.Context, user *domain.User) (codes []string, errMsg string, err error) {
	if user.TwoFactorSecret == "" || user.TwoFactorMethod != "TOTP" || user.IsTwoFactorEnabled {
		return nil, "Authenticator setup was reset. Scan the new QR code and try again.", nil
	}
	valid, err := totp.ValidateTOTPCode(user.TwoFactorSecret, c.PostForm("otp"))
	if err != nil {
		return nil, "", err
	}
	if !valid {
		return nil, "Invalid verification code. Please try again.", nil
	}
	plain, hashed, err := totp.GenerateRecoveryCodes(totp.DefaultNumRecoveryCodes, totp.DefaultRecoveryCodeLength)
	if err != nil {
		return nil, "", err
	}
	user.IsTwoFactorEnabled = true
	user.TwoFactorRecoveryCodes = hashed
	return plain, "", nil
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
