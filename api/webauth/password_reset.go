package webauth

import (
	"net/http"
	"net/mail"
	"net/url"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/pilab-dev/shadow-sso/domain"
	pkgauth "github.com/pilab-dev/shadow-sso/pkg/auth"
	"github.com/rs/zerolog/log"
)

const passwordResetTTL = 30 * time.Minute

// realm returns the current realm settings, or nil when they cannot be loaded.
func (wa *WebAuth) realm(c *gin.Context) *domain.RealmSettings {
	if wa.realmSettingsRepo == nil {
		return nil
	}
	settings, err := wa.realmSettingsRepo.GetRealmSettings(c.Request.Context())
	if err != nil {
		return nil
	}
	return settings
}

// resetPasswordAvailable renders a "not available" page and returns false when the realm
// disallows password reset or no mail provider is configured.
func (wa *WebAuth) resetPasswordAvailable(c *gin.Context) bool {
	if s := wa.realm(c); s == nil || !s.ResetPasswordAllowed || wa.emailService == nil {
		wa.renderMessage(c, http.StatusNotFound, "Not available", "Password reset is not available. Please contact your administrator.", "/login", "Back to sign in")
		return false
	}
	return true
}

// ForgotPasswordPageHandler serves GET /forgot-password.
func (wa *WebAuth) ForgotPasswordPageHandler(c *gin.Context) {
	if !wa.resetPasswordAvailable(c) {
		return
	}
	wa.renderPage(c, "forgot_password.html", "Reset password", gin.H{})
}

// ForgotPasswordSubmitHandler serves POST /forgot-password. The response never reveals whether
// the address belongs to an account.
func (wa *WebAuth) ForgotPasswordSubmitHandler(c *gin.Context) {
	if !wa.resetPasswordAvailable(c) {
		return
	}
	if !validateCSRFTokenForm(c) {
		wa.renderMessage(c, http.StatusBadRequest, "Error", "Invalid form submission. Please try again.", "/forgot-password", "Try again")
		return
	}
	email := strings.ToLower(strings.TrimSpace(c.PostForm("email")))
	const generic = "If an account exists for that address, we sent password reset instructions to it."
	done := func() { wa.renderMessage(c, http.StatusOK, "Check your email", generic, "/login", "Back to sign in") }

	key := "reset:" + c.ClientIP()
	if !wa.rateLimiter.Allow(key) {
		done() // do not signal throttling either
		return
	}
	wa.rateLimiter.RecordFailure(key)

	if _, err := mail.ParseAddress(email); err != nil {
		done()
		return
	}
	ctx := c.Request.Context()
	user, err := wa.userRepo.GetUserByEmail(ctx, email)
	if err != nil || user == nil || user.Status != domain.UserStatusActive {
		done()
		return
	}

	token, digest, err := newEmailToken()
	if err != nil {
		log.Error().Err(err).Msg("forgot password: token generation failed")
		done()
		return
	}
	if err := wa.userRepo.StorePasswordResetToken(ctx, user.ID, digest, time.Now().Add(passwordResetTTL)); err != nil {
		log.Error().Err(err).Str("user_id", user.ID).Msg("forgot password: storing token failed")
		done()
		return
	}
	link := wa.baseURL(c) + "/reset-password?token=" + url.QueryEscape(token)
	if err := wa.emailService.SendPasswordResetEmail(user.Email, displayName(user), link); err != nil {
		log.Error().Err(err).Str("user_id", user.ID).Msg("forgot password: sending email failed")
	}
	done()
}

// userForResetToken resolves and validates an emailed reset token.
func (wa *WebAuth) userForResetToken(c *gin.Context, token string) *domain.User {
	if token == "" {
		return nil
	}
	user, err := wa.userRepo.GetUserByPasswordResetToken(c.Request.Context(), hashEmailToken(token))
	if err != nil || user == nil || user.PasswordResetTokenExpiresAt == nil ||
		time.Now().After(*user.PasswordResetTokenExpiresAt) || user.Status != domain.UserStatusActive {
		return nil
	}
	return user
}

// ResetPasswordPageHandler serves GET /reset-password?token=.
func (wa *WebAuth) ResetPasswordPageHandler(c *gin.Context) {
	if !wa.resetPasswordAvailable(c) {
		return
	}
	token := c.Query("token")
	if wa.userForResetToken(c, token) == nil {
		wa.renderMessage(c, http.StatusBadRequest, "Link expired", "This password reset link is invalid or has expired.", "/forgot-password", "Request a new link")
		return
	}
	wa.renderPage(c, "reset_password.html", "Choose a new password", gin.H{"Token": token})
}

// ResetPasswordSubmitHandler serves POST /reset-password.
func (wa *WebAuth) ResetPasswordSubmitHandler(c *gin.Context) {
	if !wa.resetPasswordAvailable(c) {
		return
	}
	if !validateCSRFTokenForm(c) {
		wa.renderMessage(c, http.StatusBadRequest, "Error", "Invalid form submission. Please try again.", "/forgot-password", "Try again")
		return
	}
	token := c.PostForm("token")
	user := wa.userForResetToken(c, token)
	if user == nil {
		wa.renderMessage(c, http.StatusBadRequest, "Link expired", "This password reset link is invalid or has expired.", "/forgot-password", "Request a new link")
		return
	}

	newPassword := c.PostForm("new_password")
	switch {
	case newPassword != c.PostForm("confirm_password"):
		wa.renderPage(c, "reset_password.html", "Choose a new password", gin.H{"Token": token, "Error": "The passwords do not match."})
		return
	default:
		if err := pkgauth.ValidatePassword(newPassword, wa.passwordPolicy(c.Request.Context())); err != nil {
			wa.renderPage(c, "reset_password.html", "Choose a new password", gin.H{"Token": token, "Error": err.Error()})
			return
		}
	}

	hash, err := wa.passwordHasher.Hash(newPassword)
	if err != nil {
		log.Error().Err(err).Msg("reset password: hashing failed")
		wa.renderInternalError(c, "Could not update your password. Please try again.")
		return
	}
	user.PasswordHash = hash
	user.PasswordResetToken, user.PasswordResetTokenExpiresAt = "", nil // single use
	user.RemoveRequiredAction(domain.RequiredActionUpdatePassword)
	// Following the emailed link proves control of the mailbox.
	user.IsEmailVerified = true
	user.RemoveRequiredAction(domain.RequiredActionVerifyEmail)
	if err := wa.userRepo.UpdateUser(c.Request.Context(), user); err != nil {
		log.Error().Err(err).Str("user_id", user.ID).Msg("reset password: persist failed")
		wa.renderInternalError(c, "Could not update your password. Please try again.")
		return
	}
	// Failed-login lockouts should not outlive a successful reset.
	wa.resetLoginFailures(c.Request.Context(), user.ID)
	log.Info().Str("user_id", user.ID).Msg("password reset completed")
	wa.renderMessage(c, http.StatusOK, "Password updated", "Your password was changed. You can now sign in.", "/login", "Sign in")
}
