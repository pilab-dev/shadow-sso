package webauth

import "github.com/gin-gonic/gin"

// RegisterRoutes mounts all server-side web authentication UI routes onto the
// provided Gin engine. These are product (portal) routes, not OIDC protocol
// endpoints, but they share the same HTTP server.
func (wa *WebAuth) RegisterRoutes(router *gin.Engine) {
	// HTML responses of these routes are translated per request (see i18n.go).
	r := router.Group("")
	r.Use(wa.i18nMiddleware())

	r.GET("/", wa.LandingPageHandler)
	r.GET("/login", wa.LoginPageHandler)
	r.POST("/login", wa.LoginSubmitHandler)
	r.GET("/fedcm/close", wa.FedCMClosePageHandler)
	r.POST("/login/select", wa.SelectAccountHandler)
	r.GET("/login/:provider", wa.SocialLoginHandler)
	r.POST("/login/select-account", wa.SelectAccountSubmitHandler)
	r.GET("/consent", wa.ConsentPageHandler)
	r.POST("/consent", wa.ConsentSubmitHandler)
	r.GET("/oauth2/device/verify", wa.DeviceVerificationPageHandler)
	r.POST("/oauth2/device/verify", wa.DeviceVerificationSubmitHandler)
	r.POST("/login/passkey/begin", wa.PasskeyLoginBeginHandler)
	r.POST("/login/passkey/finish", wa.PasskeyLoginFinishHandler)
	r.GET("/account/passkeys", wa.AccountPasskeysPageHandler())
	r.POST("/account/passkeys/register/begin", wa.PasskeyRegisterBeginHandler())
	r.POST("/account/passkeys/register/finish", wa.PasskeyRegisterFinishHandler())
	r.POST("/account/passkeys/delete", wa.PasskeyDeleteSubmitHandler())
	r.GET("/account", wa.AccountOverviewHandler())
	r.POST("/account/profile", wa.AccountProfileSubmitHandler())
	r.GET("/account/security", wa.AccountSecurityHandler())
	r.POST("/account/password", wa.AccountPasswordSubmitHandler())
	r.GET("/account/mfa/totp", wa.AccountTOTPPageHandler())
	r.POST("/account/mfa/totp", wa.AccountTOTPSubmitHandler())
	r.POST("/account/mfa/recovery", wa.AccountRecoveryCodesSubmitHandler())
	r.POST("/account/mfa/disable", wa.AccountMFADisableSubmitHandler())
	r.GET("/account/sessions", wa.AccountSessionsHandler())
	r.POST("/account/sessions/revoke", wa.AccountSessionRevokeHandler())
	r.GET("/account/linked", wa.AccountLinkedHandler())
	r.POST("/account/linked/unlink", wa.AccountUnlinkSubmitHandler())
	r.POST("/account/logout", wa.AccountLogoutSubmitHandler())
	r.GET("/forgot-password", wa.ForgotPasswordPageHandler)
	r.POST("/forgot-password", wa.ForgotPasswordSubmitHandler)
	r.GET("/reset-password", wa.ResetPasswordPageHandler)
	r.POST("/reset-password", wa.ResetPasswordSubmitHandler)
	r.GET("/register", wa.RegisterPageHandler)
	r.POST("/register", wa.RegisterSubmitHandler)
	r.GET("/verify-email", wa.VerifyEmailHandler)
	r.GET("/required-action", wa.RequiredActionPageHandler)
	r.POST("/required-action", wa.RequiredActionSubmitHandler)
	r.POST("/mfa", wa.MFASubmitHandler)
	r.POST("/mfa/resend", wa.MFAResendSubmitHandler)
	r.GET("/mfa/enroll", wa.MFAEnrollPageHandler)
	r.POST("/mfa/enroll", wa.MFAEnrollSubmitHandler)
	r.POST("/mfa/enroll/complete", wa.MFAEnrollCompleteHandler)
	r.GET("/api/session", wa.SessionHandler)
}
