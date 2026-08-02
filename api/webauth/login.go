package webauth

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/pilab-dev/shadow-sso/domain"
	"github.com/pilab-dev/shadow-sso/internal/ssosession"
	"github.com/rs/zerolog/log"
)

func (wa *WebAuth) renderLoginPage(c *gin.Context, flowID string, providers []*domain.IdentityProvider, errMsg string) {
	csrfToken, err := generateCSRFToken()
	if err != nil {
		log.Error().Err(err).Msg("login: failed to generate CSRF token")
		c.HTML(http.StatusInternalServerError, "error.html", gin.H{
			"PageTitle": "Error",
			"Message":   "Internal error. Please try again.",
		})
		return
	}

	isSecure := IsSecureRequest(c.Request)
	setCSRFCookie(c.Writer, csrfToken, 10*time.Minute, isSecure)

	c.HTML(http.StatusOK, "login.html", gin.H{
		"PageTitle":  "Sign In",
		"FlowID":     flowID,
		"CSRFToken":  csrfToken,
		"Providers":  providers,
		"BrandLogo":  wa.config.BrandLogoURL,
		"BrandName":  wa.config.BrandOrganizationName,
		"BrandColor": wa.config.BrandPrimaryColor,
		"Error":      errMsg,
	})
}

// LoginPageHandler serves the GET /login page.
// It validates the flow, loads social providers, and renders the login form.
func (wa *WebAuth) LoginPageHandler(c *gin.Context) {
	flowID := GetFlowIDFromCookie(c.Request)

	if flowID == "" {
		c.HTML(http.StatusBadRequest, "error.html", gin.H{
			"PageTitle": "Error",
			"Message":   "Missing login request identifier.",
		})
		return
	}

	ctx := c.Request.Context()

	flowState, err := wa.flowStore.GetFlow(ctx, flowID)
	if err != nil {
		log.Warn().Err(err).Str("flow_id", flowID).Msg("login: flow not found")
		c.HTML(http.StatusBadRequest, "error.html", gin.H{
			"PageTitle": "Error",
			"Message":   "Invalid or expired login request.",
		})
		return
	}
	if time.Now().After(flowState.ExpiresAt) {
		log.Warn().Str("flow_id", flowID).Msg("login: flow expired")
		_ = wa.flowStore.DeleteFlow(ctx, flowID)
		c.HTML(http.StatusBadRequest, "error.html", gin.H{
			"PageTitle": "Error",
			"Message":   "Login request has expired. Please try again.",
		})
		return
	}

	// Load social providers only after the flow has been validated.
	providers, err := wa.idpRepo.ListIdPs(ctx, true)
	if err != nil {
		log.Error().Err(err).Msg("login: failed to load identity providers")
		providers = nil
	}

	errorMsg := c.Query("error")
	wa.renderLoginPage(c, flowID, providers, errorMsg)
}

// accountLockedOut reports whether a user's account is currently locked due to
// repeated failed login attempts. Persistent lockout is only applied when the
// realm has brute-force protection enabled; the in-memory RateLimiter remains
// a secondary, per-IP defense layer.
func (wa *WebAuth) accountLockedOut(ctx context.Context, user *domain.User) bool {
	if wa.realmSettingsRepo == nil {
		return false
	}
	settings, err := wa.realmSettingsRepo.GetRealmSettings(ctx)
	if err != nil || settings == nil || !settings.BruteForceProtected {
		return false
	}
	if user.FailedLoginAttempts < wa.config.RateLimitMaxAttempts {
		return false
	}
	if user.LastFailedLoginTime == nil {
		return false
	}
	return time.Since(*user.LastFailedLoginTime) < wa.config.RateLimitLockoutDuration
}

// recordLoginFailure increments the persistent failed-attempt counter when the
// realm has brute-force protection enabled. It is best-effort: repository
// errors are logged and swallowed so the login flow's own error path is not
// masked by bookkeeping failures.
func (wa *WebAuth) recordLoginFailure(ctx context.Context, userID string) {
	if wa.realmSettingsRepo == nil {
		return
	}
	settings, err := wa.realmSettingsRepo.GetRealmSettings(ctx)
	if err != nil || settings == nil || !settings.BruteForceProtected {
		return
	}
	if _, err := wa.userRepo.IncrementFailedLoginAttempts(ctx, userID); err != nil {
		log.Warn().Err(err).Str("user_id", userID).Msg("login: failed to increment failed login attempts")
	}
}

// resetLoginFailures clears the persistent failed-attempt counter on a
// successful login when brute-force protection is enabled.
func (wa *WebAuth) resetLoginFailures(ctx context.Context, userID string) {
	if wa.realmSettingsRepo == nil {
		return
	}
	settings, err := wa.realmSettingsRepo.GetRealmSettings(ctx)
	if err != nil || settings == nil || !settings.BruteForceProtected {
		return
	}
	if err := wa.userRepo.ResetFailedLoginAttempts(ctx, userID); err != nil {
		log.Warn().Err(err).Str("user_id", userID).Msg("login: failed to reset failed login attempts")
	}
}

// LoginSubmitHandler processes the POST /login form submission.
// It validates CSRF, checks rate limits, authenticates the user, creates an
// SSO session cookie, and redirects to the next step in the flow.
func (wa *WebAuth) LoginSubmitHandler(c *gin.Context) {
	if !validateCSRFTokenForm(c) {
		c.HTML(http.StatusBadRequest, "error.html", gin.H{
			"PageTitle": "Error",
			"Message":   "Invalid form submission. Please try again.",
		})
		return
	}

	flowID := GetFlowIDFromCookie(c.Request)
	email := c.PostForm("email")
	password := c.PostForm("password")

	if flowID == "" || email == "" || password == "" {
		wa.renderLoginPage(c, flowID, nil, "All fields are required.")
		return
	}

	rateLimitKey := c.ClientIP() + ":" + email
	if !wa.rateLimiter.Allow(rateLimitKey) {
		log.Warn().Str("email", email).Str("ip", c.ClientIP()).Msg("login: rate limited")
		wa.renderLoginPage(c, flowID, nil, "Too many attempts. Please try again later.")
		return
	}

	ctx := c.Request.Context()

	flowState, err := wa.flowStore.GetFlow(ctx, flowID)
	if err != nil {
		log.Warn().Err(err).Str("flow_id", flowID).Msg("login: flow not found on submit")
		c.HTML(http.StatusBadRequest, "error.html", gin.H{
			"PageTitle": "Error",
			"Message":   "Invalid or expired login request.",
		})
		return
	}
	if time.Now().After(flowState.ExpiresAt) {
		log.Warn().Str("flow_id", flowID).Msg("login: flow expired on submit")
		_ = wa.flowStore.DeleteFlow(ctx, flowID)
		c.HTML(http.StatusBadRequest, "error.html", gin.H{
			"PageTitle": "Error",
			"Message":   "Login request has expired. Please try again.",
		})
		return
	}

	user, err := wa.userRepo.GetUserByEmail(ctx, email)
	if err != nil {
		wa.rateLimiter.RecordFailure(rateLimitKey)
		log.Warn().Err(err).Str("email", email).Msg("login: user not found")
		wa.renderLoginPage(c, flowID, nil, "Invalid email or password.")
		return
	}

	if wa.accountLockedOut(ctx, user) {
		wa.rateLimiter.RecordFailure(rateLimitKey)
		log.Warn().Str("email", email).Str("user_id", user.ID).Msg("login: account locked out due to repeated failed attempts")
		wa.renderLoginPage(c, flowID, nil, "Account is temporarily locked. Please try again later.")
		return
	}

	requiresMFA, err := wa.runner.Authenticate(ctx, user, password)
	if err != nil {
		wa.rateLimiter.RecordFailure(rateLimitKey)
		wa.recordLoginFailure(ctx, user.ID)
		log.Warn().Str("email", email).Msg("login: password verification failed")
		wa.renderLoginPage(c, flowID, nil, "Invalid email or password.")
		return
	}

	if user.Status != domain.UserStatusActive {
		wa.rateLimiter.RecordFailure(rateLimitKey)
		wa.recordLoginFailure(ctx, user.ID)
		log.Warn().Str("email", email).Str("status", string(user.Status)).Msg("login: account not active")
		wa.renderLoginPage(c, flowID, nil, "Account is not active. Please contact support.")
		return
	}

	wa.rateLimiter.Reset(rateLimitKey)
	wa.resetLoginFailures(ctx, user.ID)

	if requiresMFA {
		flowState.UserID = user.ID
		flowState.UserAuthenticatedAt = time.Now()
		if err := wa.flowStore.UpdateFlow(ctx, flowID, flowState); err != nil {
			log.Error().Err(err).Str("flow_id", flowID).Msg("login: failed to update flow for MFA")
			c.HTML(http.StatusInternalServerError, "error.html", gin.H{
				"PageTitle": "Error",
				"Message":   "Internal error. Please try again.",
			})
			return
		}
		c.HTML(http.StatusOK, "mfa.html", gin.H{
			"PageTitle": "Two-Factor Authentication",
			"FlowID":    flowID,
			"UserID":    user.ID,
			"BrandName": wa.config.BrandOrganizationName,
		})
		return
	}

	// Record the authenticated user on the flow state so the OIDC AuthorizeHandler
	// can complete the authorization without relying on SSO session cookies.
	flowState.UserID = user.ID
	flowState.UserAuthenticatedAt = time.Now()
	if err := wa.flowStore.UpdateFlow(ctx, flowID, flowState); err != nil {
		log.Error().Err(err).Str("flow_id", flowID).Msg("login: failed to update flow state after auth")
		c.HTML(http.StatusInternalServerError, "error.html", gin.H{
			"PageTitle": "Error",
			"Message":   "Internal error. Please try again.",
		})
		return
	}

	displayName := user.Email
	if user.FirstName != "" || user.LastName != "" {
		displayName = fmt.Sprintf("%s %s", user.FirstName, user.LastName)
	}
	isSecure := IsSecureRequest(c.Request)
	session := &ssosession.Session{
		SessionID: ssosession.NewID(),
		Accounts: []ssosession.Account{{
			UserID:   user.ID,
			Email:    user.Email,
			Name:     displayName,
			LastUsed: time.Now(),
		}},
	}
	if err := SetSSOSessionCookie(c.Writer, session, isSecure, wa.ssoCookieSecret); err != nil {
		log.Error().Err(err).Msg("login: failed to set SSO session cookie")
		c.HTML(http.StatusInternalServerError, "error.html", gin.H{
			"PageTitle": "Error",
			"Message":   "Failed to create session. Please try again.",
		})
		return
	}

	requiresConsent := false
	if flowState.ClientID != "" {
		client, cErr := wa.oauthService.ValidateClient(ctx, flowState.ClientID, "")
		if cErr == nil && client != nil && client.RequireConsent {
			requiresConsent = true
		}
	}
	if requiresConsent {
		c.Redirect(http.StatusFound, "/consent?flow_id="+url.QueryEscape(flowID))
		return
	}
	c.Redirect(http.StatusFound, "/oauth2/authorize?flow_id="+url.QueryEscape(flowID))
}

// validateCSRFTokenForm validates CSRF using a hidden form field compared against
// the double-submit cookie. This differs from the header-based validation used
// by API endpoints.
func validateCSRFTokenForm(c *gin.Context) bool {
	cookieVal, err := c.Cookie(CSRFCookieName)
	if err != nil || cookieVal == "" {
		return false
	}
	formVal := c.PostForm("csrf_token")
	if formVal == "" {
		return false
	}
	return cookieVal == formVal
}
