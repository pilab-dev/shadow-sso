package webauth

import (
	"crypto/rand"
	"encoding/hex"
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

	// Accept either a single "full name" field or split first/last name fields.
	fullName := strings.TrimSpace(c.PostForm("full_name"))
	if fullName == "" {
		fullName = strings.TrimSpace(c.PostForm("name"))
	}
	if fullName == "" {
		fullName = strings.TrimSpace(c.PostForm("fullname"))
	}
	first := strings.TrimSpace(c.PostForm("first_name"))
	last := strings.TrimSpace(c.PostForm("last_name"))
	if first == "" && last == "" && fullName != "" {
		parts := strings.Fields(fullName)
		if len(parts) > 0 {
			first = parts[0]
		}
		if len(parts) > 1 {
			last = strings.Join(parts[1:], " ")
		}
	}

	// Accept several common spellings for the telephone number.
	tel := strings.TrimSpace(c.PostForm("tel"))
	if tel == "" {
		tel = strings.TrimSpace(c.PostForm("phone"))
	}
	if tel == "" {
		tel = strings.TrimSpace(c.PostForm("phone_number"))
	}
	if tel == "" {
		tel = strings.TrimSpace(c.PostForm("telephone"))
	}

	password := c.PostForm("password")
	confirm := c.PostForm("confirm_password")
	if confirm == "" {
		confirm = c.PostForm("confirm")
	}
	fail := func(msg string) {
		wa.renderPage(c, "register.html", "Create account", gin.H{
			"Error":     msg,
			"Email":     email,
			"FullName":  fullName,
			"FirstName": first,
			"LastName":  last,
			"Tel":       tel,
		})
	}

	if _, err := mail.ParseAddress(email); err != nil {
		fail("Enter a valid email address.")
		return
	}
	// Password is optional for the new flow, but when supplied it must match and
	// satisfy the password policy.
	if password != "" || confirm != "" {
		if password != confirm {
			fail("The passwords do not match.")
			return
		}
		ctx := c.Request.Context()
		if err := pkgauth.ValidatePassword(password, wa.passwordPolicy(ctx)); err != nil {
			fail(err.Error())
			return
		}
	}

	ctx := c.Request.Context()
	existing, _ := wa.userRepo.GetUserByEmail(ctx, email)
	if existing != nil {
		if existing.PasswordHash == "" {
			fail("An account with this email is already registered via a federated provider. You must log in with that provider, then you can initiate account pairing.")
			return
		}
		fail("An account with this email already exists.")
		return
	}

	// Hash the password, generating an unguessable one when none was supplied so
	// the account cannot be accessed with an empty password.
	var hash string
	if password != "" {
		h, err := wa.passwordHasher.Hash(password)
		if err != nil {
			log.Error().Err(err).Msg("register: hashing failed")
			wa.renderInternalError(c, "Could not create your account. Please try again.")
			return
		}
		hash = h
	} else {
		randomPw := make([]byte, 32)
		if _, err := rand.Read(randomPw); err != nil {
			log.Error().Err(err).Msg("register: random generation failed")
			wa.renderInternalError(c, "Could not create your account. Please try again.")
			return
		}
		h, err := wa.passwordHasher.Hash(hex.EncodeToString(randomPw))
		if err != nil {
			log.Error().Err(err).Msg("register: hashing failed")
			wa.renderInternalError(c, "Could not create your account. Please try again.")
			return
		}
		hash = h
	}

	user := &domain.User{
		Email:        email,
		PasswordHash: hash,
		FirstName:    first,
		LastName:     last,
		PhoneNumber:  tel,
		Status:       domain.UserStatusActive,
		// Explicit roles: with none set, the repository grants ADMIN to the very first user in an
		// empty database, which must never happen through public registration.
		Roles: []string{rbac.RoleUser},
	}
	if realm.VerifyEmail && wa.emailService != nil {
		user.AddRequiredAction(domain.RequiredActionVerifyEmail)
		user.Status = domain.UserStatusPending
	}
	if err := wa.userRepo.CreateUser(ctx, user); err != nil {
		log.Error().Err(err).Msg("register: create user failed")
		fail("Could not create your account. Please try again.")
		return
	}
	log.Info().Str("user_id", user.ID).Msg("user self-registered")

	// Send a validation email containing a strong (non-UUID) link so the
	// registration session can be continued out of band.
	if realm.VerifyEmail && wa.emailService != nil {
		if err := wa.sendVerificationEmail(c, user); err != nil {
			log.Error().Err(err).Str("user_id", user.ID).Msg("register: send verification email failed")
		}
	}

	// If the user came from an OIDC authorization request, sign them straight in (running any
	// required actions such as email verification); otherwise point them at the login page.
	if flowID := GetFlowIDFromCookie(c.Request); flowID != "" {
		if flowState, err := wa.flowStore.GetFlow(ctx, flowID); err == nil && flowState != nil && flowState.ExpiresAt.After(time.Now()) {
			wa.finishLogin(c, ctx, flowID, flowState, user)
			return
		}
	}
	if realm.VerifyEmail && wa.emailService != nil {
		wa.renderMessage(c, http.StatusOK, "Account created", "We sent a validation link to your email. Open it to continue your registration.", "/login", "Back to sign in")
		return
	}
	wa.renderMessage(c, http.StatusOK, "Account created", "Your account was created. You can now sign in.", "/login", "Sign in")
}
