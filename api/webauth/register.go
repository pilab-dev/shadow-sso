package webauth

import (
	"net/http"
	"net/mail"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/pilab-dev/shadow-sso/domain"
	"github.com/pilab-dev/shadow-sso/internal/auth/rbac"
	pkgauth "github.com/pilab-dev/shadow-sso/pkg/auth"
	"github.com/rs/zerolog/log"
)

// registrationAvailable renders a "not available" page and returns false when self-registration is off.
func (wa *WebAuth) registrationAvailable(c *gin.Context) bool {
	if s := wa.realm(c); s == nil || !s.RegistrationAllowed {
		wa.renderMessage(c, http.StatusNotFound, "Not available", "Self-registration is not enabled.", "/login", "Back to sign in")
		return false
	}
	return true
}

// RegisterPageHandler serves GET /register.
func (wa *WebAuth) RegisterPageHandler(c *gin.Context) {
	if !wa.registrationAvailable(c) {
		return
	}
	wa.renderPage(c, "register.html", "Create account", gin.H{})
}

// RegisterSubmitHandler serves POST /register.
func (wa *WebAuth) RegisterSubmitHandler(c *gin.Context) {
	realm := wa.realm(c)
	if realm == nil || !realm.RegistrationAllowed {
		wa.renderMessage(c, http.StatusNotFound, "Not available", "Self-registration is not enabled.", "/login", "Back to sign in")
		return
	}
	if !validateCSRFTokenForm(c) {
		wa.renderMessage(c, http.StatusBadRequest, "Error", "Invalid form submission. Please try again.", "/register", "Try again")
		return
	}

	key := "register:" + c.ClientIP()
	if !wa.rateLimiter.Allow(key) {
		wa.renderMessage(c, http.StatusTooManyRequests, "Too many attempts", "Please try again later.", "/login", "Back to sign in")
		return
	}
	wa.rateLimiter.RecordFailure(key)

	email := strings.ToLower(strings.TrimSpace(c.PostForm("email")))
	first := strings.TrimSpace(c.PostForm("first_name"))
	last := strings.TrimSpace(c.PostForm("last_name"))
	password := c.PostForm("password")
	fail := func(msg string) {
		wa.renderPage(c, "register.html", "Create account", gin.H{"Error": msg, "Email": email, "FirstName": first, "LastName": last})
	}

	if _, err := mail.ParseAddress(email); err != nil {
		fail("Enter a valid email address.")
		return
	}
	if password != c.PostForm("confirm_password") {
		fail("The passwords do not match.")
		return
	}
	ctx := c.Request.Context()
	if err := pkgauth.ValidatePassword(password, wa.passwordPolicy(ctx)); err != nil {
		fail(err.Error())
		return
	}
	if existing, err := wa.userRepo.GetUserByEmail(ctx, email); err == nil && existing != nil {
		fail("An account with this email already exists.")
		return
	}

	hash, err := wa.passwordHasher.Hash(password)
	if err != nil {
		log.Error().Err(err).Msg("register: hashing failed")
		wa.renderInternalError(c, "Could not create your account. Please try again.")
		return
	}
	user := &domain.User{
		Email:        email,
		PasswordHash: hash,
		FirstName:    first,
		LastName:     last,
		Status:       domain.UserStatusActive,
		// Explicit roles: with none set, the repository grants ADMIN to the very first user in an
		// empty database, which must never happen through public registration.
		Roles: []string{rbac.RoleUser},
	}
	if realm.VerifyEmail && wa.emailService != nil {
		user.AddRequiredAction(domain.RequiredActionVerifyEmail)
	}
	if err := wa.userRepo.CreateUser(ctx, user); err != nil {
		log.Error().Err(err).Msg("register: create user failed")
		fail("Could not create your account. Please try again.")
		return
	}
	log.Info().Str("user_id", user.ID).Msg("user self-registered")

	// If the user came from an OIDC authorization request, sign them straight in (running any
	// required actions such as email verification); otherwise point them at the login page.
	if flowID := GetFlowIDFromCookie(c.Request); flowID != "" {
		if flowState, err := wa.flowStore.GetFlow(ctx, flowID); err == nil && flowState != nil && flowState.ExpiresAt.After(time.Now()) {
			wa.finishLogin(c, ctx, flowID, flowState, user)
			return
		}
	}
	wa.renderMessage(c, http.StatusOK, "Account created", "Your account was created. You can now sign in.", "/login", "Sign in")
}
