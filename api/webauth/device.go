package webauth

import (
	"errors"
	"net/http"
	"net/url"

	"github.com/gin-gonic/gin"
	"github.com/pilab-dev/shadow-sso/domain"
	"github.com/rs/zerolog/log"
)

// deviceVerifyPath is the route path served by the device verification page.
const deviceVerifyPath = "/oauth2/device/verify"

// deviceLoginRedirectURL builds the login redirect that returns the user to
// the device verification page (with the code preserved) after authenticating.
func deviceLoginRedirectURL(userCode string) string {
	verifyPath := deviceVerifyPath
	if userCode != "" {
		verifyPath += "?user_code=" + url.QueryEscape(userCode)
	}
	return "/login?return_to=" + url.QueryEscape(verifyPath)
}

// deviceErrorText maps a device-code verification failure to the user-facing
// message, mirroring the strings previously used by the openidv2_1 handler.
func deviceErrorText(err error) string {
	switch {
	case errors.Is(err, domain.ErrUserCodeNotFound):
		return "Invalid or expired code. Please check the code and try again."
	case errors.Is(err, domain.ErrCannotApproveDeviceAuth):
		return "This code cannot be used. It might have already been activated or is invalid."
	default:
		return "An unexpected error occurred. Please try again later."
	}
}

// DeviceVerificationPageHandler serves GET /oauth2/device/verify. Authenticated
// users see the code and the requesting application with Approve/Deny actions;
// unauthenticated users are redirected to /login and returned here afterwards.
func (wa *WebAuth) DeviceVerificationPageHandler(c *gin.Context) {
	userCode := c.Query("user_code")

	if _, err := GetSSOSession(c.Request, wa.ssoCookieSecret); err != nil {
		c.Redirect(http.StatusFound, deviceLoginRedirectURL(userCode))
		return
	}

	data := gin.H{
		"UserCode":    userCode,
		"ClientName":  "an application",
		"Message":     "",
		"MessageType": "",
	}

	if userCode != "" {
		if wa.deviceAuthRepo == nil {
			log.Error().Msg("device: deviceAuthRepo is nil")
			c.HTML(http.StatusInternalServerError, "error.html", gin.H{
				"PageTitle": "Error",
				"Message":   "Device authorization is not available. Please try again later.",
			})
			return
		}

		dc, err := wa.deviceAuthRepo.GetDeviceAuthByUserCode(c.Request.Context(), userCode)
		if err != nil {
			if errors.Is(err, domain.ErrUserCodeNotFound) {
				log.Warn().Str("user_code", userCode).Msg("device: code not found")
				data["Message"] = deviceErrorText(domain.ErrUserCodeNotFound)
				data["MessageType"] = "error"
			} else {
				log.Error().Err(err).Str("user_code", userCode).Msg("device: failed to load device code")
				c.HTML(http.StatusInternalServerError, "error.html", gin.H{
					"PageTitle": "Error",
					"Message":   "Failed to load device authorization. Please try again.",
				})
				return
			}
		} else if dc != nil {
			if client, cErr := wa.clientService.GetClient(c.Request.Context(), dc.ClientID); cErr == nil && client != nil && client.Name != "" {
				data["ClientName"] = client.Name
			}
		}
	}

	wa.renderTemplate(c, "device.html", data)
}

// DeviceVerificationSubmitHandler processes POST /oauth2/device/verify. It
// validates CSRF, requires an authenticated session, then approves the code via
// VerifyUserCode or denies it via UpdateDeviceAuthStatus.
func (wa *WebAuth) DeviceVerificationSubmitHandler(c *gin.Context) {
	if !validateCSRFTokenForm(c) {
		c.HTML(http.StatusBadRequest, "error.html", gin.H{
			"PageTitle": "Error",
			"Message":   "Invalid form submission. Please try again.",
		})
		return
	}

	userCode := c.PostForm("user_code")
	action := c.PostForm("action")

	session, err := GetSSOSession(c.Request, wa.ssoCookieSecret)
	if err != nil || len(session.Accounts) == 0 {
		c.Redirect(http.StatusFound, deviceLoginRedirectURL(userCode))
		return
	}
	userID := session.Accounts[0].UserID

	ctx := c.Request.Context()

	if action == "deny" {
		if wa.deviceAuthRepo == nil {
			log.Error().Msg("device: deviceAuthRepo is nil on deny")
			c.HTML(http.StatusInternalServerError, "error.html", gin.H{
				"PageTitle": "Error",
				"Message":   "Device authorization is not available. Please try again later.",
			})
			return
		}

		dc, dErr := wa.deviceAuthRepo.GetDeviceAuthByUserCode(ctx, userCode)
		if dErr != nil || dc == nil {
			log.Warn().Err(dErr).Str("user_code", userCode).Msg("device: code not found on deny")
			wa.renderTemplate(c, "device.html", gin.H{
				"UserCode":    userCode,
				"Message":     deviceErrorText(domain.ErrUserCodeNotFound),
				"MessageType": "error",
			})
			return
		}
		if uErr := wa.deviceAuthRepo.UpdateDeviceAuthStatus(ctx, dc.DeviceCode, domain.DeviceCodeStatusDenied); uErr != nil {
			log.Error().Err(uErr).Str("device_code", dc.DeviceCode).Msg("device: failed to deny device code")
			wa.renderTemplate(c, "device.html", gin.H{
				"UserCode":    userCode,
				"Message":     deviceErrorText(uErr),
				"MessageType": "error",
			})
			return
		}

		log.Info().Str("device_code", dc.DeviceCode).Str("user_id", userID).Msg("device: access denied by user")
		wa.renderTemplate(c, "device.html", gin.H{
			"UserCode":    userCode,
			"Message":     "Device access denied.",
			"MessageType": "success",
		})
		return
	}

	if _, vErr := wa.oauthService.VerifyUserCode(ctx, userCode, userID); vErr != nil {
		log.Warn().Err(vErr).Str("user_code", userCode).Str("user_id", userID).Msg("device: failed to verify user code")
		wa.renderTemplate(c, "device.html", gin.H{
			"UserCode":    userCode,
			"Message":     deviceErrorText(vErr),
			"MessageType": "error",
		})
		return
	}

	log.Info().Str("user_code", userCode).Str("user_id", userID).Msg("device: code verified and linked to user")
	wa.renderTemplate(c, "device.html", gin.H{
		"UserCode":    userCode,
		"Message":     "Device activated successfully! You can now return to your device.",
		"MessageType": "success",
	})
}
