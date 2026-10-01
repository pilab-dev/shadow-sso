package webauth

import (
	"context"
	"net/http"
	"net/url"
	"sort"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
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

// tryRenderAccountSelector renders account_selector.html (a Google-style
// "choose an account" chooser) when the browser already carries an
// sso_session cookie with one or more cached accounts, and the caller has not
// asked to bypass it with ?new_account=1 (the "Use another account" link).
// Returns true if it rendered a response, in which case the caller must not
// render anything else.
func (wa *WebAuth) tryRenderAccountSelector(c *gin.Context, flowID string) bool {
	if c.Query("new_account") != "" {
		return false
	}
	session, err := GetSSOSession(c.Request, wa.ssoCookieSecret)
	if err != nil || session == nil || len(session.Accounts) == 0 {
		return false
	}

	accounts := make([]ssosession.Account, len(session.Accounts))
	copy(accounts, session.Accounts)
	sort.SliceStable(accounts, func(i, j int) bool {
		return accounts[i].LastUsed.After(accounts[j].LastUsed)
	})

	csrfToken, err := generateCSRFToken()
	if err != nil {
		log.Error().Err(err).Msg("login: failed to generate CSRF token for account selector")
		c.HTML(http.StatusInternalServerError, "error.html", gin.H{
			"PageTitle": "Error",
			"Message":   "Internal error. Please try again.",
		})
		return true
	}
	isSecure := IsSecureRequest(c.Request)
	setCSRFCookie(c.Writer, csrfToken, 10*time.Minute, isSecure)

	c.HTML(http.StatusOK, "account_selector.html", gin.H{
		"PageTitle":  "Choose an account",
		"FlowID":     flowID,
		"CSRFToken":  csrfToken,
		"Accounts":   accounts,
		"BrandLogo":  wa.config.BrandLogoURL,
		"BrandName":  wa.config.BrandOrganizationName,
		"BrandColor": wa.config.BrandPrimaryColor,
	})
	return true
}

// LoginPageHandler serves the GET /login page.
// It validates the flow, loads social providers, and renders the login form.
func (wa *WebAuth) LoginPageHandler(c *gin.Context) {
	flowID := GetFlowIDFromCookie(c.Request)

	if flowID == "" {
		// Flow-less login: when no sso_oidc_flow_id cookie exists but a
		// validated same-origin return_to is present (e.g. the device
		// verification redirect), start a synthetic flow so the login page
		// renders instead of failing with 400.
		if rt := c.Query("return_to"); rt != "" && validReturnTo(rt) {
			ctx := c.Request.Context()
			flowID = uuid.NewString()
			flowState := &domain.LoginFlowState{
				FlowID:    flowID,
				ExpiresAt: time.Now().Add(syntheticFlowLifetime),
			}
			if err := wa.flowStore.StoreFlow(ctx, flowID, *flowState); err != nil {
				log.Error().Err(err).Str("flow_id", flowID).Msg("login: failed to store synthetic flow")
				c.HTML(http.StatusInternalServerError, "error.html", gin.H{
					"PageTitle": "Error",
					"Message":   "Internal error. Please try again.",
				})
				return
			}
			isSecure := IsSecureRequest(c.Request)
			setFlowCookie(c.Writer, flowID, isSecure)
			setReturnToCookie(c.Writer, rt, isSecure, wa.ssoCookieSecret)

			if wa.tryRenderAccountSelector(c, flowID) {
				return
			}

			providers, err := wa.idpRepo.ListIdPs(ctx, true)
			if err != nil {
				log.Error().Err(err).Msg("login: failed to load identity providers")
				providers = nil
			}
			wa.renderLoginPage(c, flowID, providers, "")
			return
		}
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

	if wa.tryRenderAccountSelector(c, flowID) {
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
		// The password step passed but the second factor has not: the flow must not
		// yield an authorization code until /mfa clears this marker.
		flowState.Pending = domain.FlowPendingMFA
		if err := wa.flowStore.UpdateFlow(ctx, flowID, flowState); err != nil {
			log.Error().Err(err).Str("flow_id", flowID).Msg("login: failed to update flow for MFA")
			c.HTML(http.StatusInternalServerError, "error.html", gin.H{
				"PageTitle": "Error",
				"Message":   "Internal error. Please try again.",
			})
			return
		}

		if user.TwoFactorMethod == "EMAIL" {
			if wa.mfaService == nil {
				log.Error().Str("flow_id", flowID).Msg("login: email MFA required but MFA service is not configured")
				c.HTML(http.StatusInternalServerError, "error.html", gin.H{
					"PageTitle": "Error",
					"Message":   "Email verification is not available. Please contact support.",
				})
				return
			}
			if _, _, _, err := wa.mfaService.SendMFAChallenge(ctx, user.ID); err != nil {
				log.Error().Err(err).Str("flow_id", flowID).Msg("login: failed to send email MFA challenge")
				c.HTML(http.StatusInternalServerError, "error.html", gin.H{
					"PageTitle": "Error",
					"Message":   "Failed to send verification code. Please try again.",
				})
				return
			}
		}

		wa.renderMFAPage(c, flowID, user.TwoFactorMethod, user.Email, "")
		return
	}

	// finishLogin records the user on the flow, runs pending required actions, issues the
	// SSO cookie and continues to consent/authorization.
	wa.finishLogin(c, ctx, flowID, flowState, user)
}

// redirectAfterAuthentication completes a login (password, MFA, or cached
// account selection) by sending the browser to consent, the return_to
// destination for flow-less logins, or back into the OIDC authorize step.
func (wa *WebAuth) redirectAfterAuthentication(c *gin.Context, ctx context.Context, flowID string, flowState *domain.LoginFlowState, isSecure bool) {
	requiresConsent := false
	if flowState.ClientID != "" && wa.oauthService != nil {
		client, cErr := wa.oauthService.ValidateClient(ctx, flowState.ClientID, "")
		if cErr == nil && client != nil && client.RequireConsent {
			requiresConsent = true
		}
	}
	if requiresConsent {
		c.Redirect(http.StatusFound, "/consent?flow_id="+url.QueryEscape(flowID))
		return
	}
	if flowState.ClientID == "" {
		// Flow-less login (no OIDC client): complete by redirecting to the
		// signed return_to destination captured when the synthetic flow began.
		// The cookie is cleared on use; fall back to "/" when absent or invalid.
		rt := readReturnToCookie(c.Request, wa.ssoCookieSecret)
		clearReturnToCookie(c.Writer, isSecure)
		if rt != "" && validReturnTo(rt) {
			c.Redirect(http.StatusFound, rt)
			return
		}
		c.Redirect(http.StatusFound, "/")
		return
	}
	c.Redirect(http.StatusFound, "/oauth2/authorize?flow_id="+url.QueryEscape(flowID))
}

// SelectAccountSubmitHandler processes POST /login/select-account: the user
// picked a cached account from account_selector.html. It re-authenticates by
// trust in the existing sso_session cookie (the account was already fully
// authenticated, including MFA, when it was added to the session) rather than
// prompting for a password again — the same behavior as Google's account
// chooser.
func (wa *WebAuth) SelectAccountSubmitHandler(c *gin.Context) {
	if !validateCSRFTokenForm(c) {
		c.HTML(http.StatusBadRequest, "error.html", gin.H{
			"PageTitle": "Error",
			"Message":   "Invalid form submission. Please try again.",
		})
		return
	}

	flowID := c.PostForm("flow_id")
	userID := c.PostForm("user_id")
	if flowID == "" || userID == "" {
		c.HTML(http.StatusBadRequest, "error.html", gin.H{
			"PageTitle": "Error",
			"Message":   "Invalid or expired login request. Please try again.",
		})
		return
	}

	ctx := c.Request.Context()

	flowState, err := wa.flowStore.GetFlow(ctx, flowID)
	if err != nil {
		log.Warn().Err(err).Str("flow_id", flowID).Msg("select-account: flow not found")
		c.HTML(http.StatusBadRequest, "error.html", gin.H{
			"PageTitle": "Error",
			"Message":   "Invalid or expired login request.",
		})
		return
	}
	if time.Now().After(flowState.ExpiresAt) {
		log.Warn().Str("flow_id", flowID).Msg("select-account: flow expired")
		_ = wa.flowStore.DeleteFlow(ctx, flowID)
		c.HTML(http.StatusBadRequest, "error.html", gin.H{
			"PageTitle": "Error",
			"Message":   "Login request has expired. Please try again.",
		})
		return
	}

	session, err := GetSSOSession(c.Request, wa.ssoCookieSecret)
	if err != nil || session == nil {
		log.Warn().Str("flow_id", flowID).Msg("select-account: no sso_session cookie")
		c.Redirect(http.StatusFound, "/login?new_account=1")
		return
	}
	found := false
	for _, a := range session.Accounts {
		if a.UserID == userID {
			found = true
			break
		}
	}
	if !found {
		log.Warn().Str("flow_id", flowID).Str("user_id", userID).Msg("select-account: user not in sso_session cookie")
		c.Redirect(http.StatusFound, "/login?new_account=1")
		return
	}

	user, err := wa.userRepo.GetUserByID(ctx, userID)
	if err != nil || user.Status != domain.UserStatusActive {
		log.Warn().Err(err).Str("flow_id", flowID).Str("user_id", userID).Msg("select-account: user not found or inactive")
		c.HTML(http.StatusBadRequest, "error.html", gin.H{
			"PageTitle": "Error",
			"Message":   "This account is no longer available. Please sign in again.",
		})
		return
	}

	flowState.UserAuthenticatedAt = time.Now()
	wa.finishLogin(c, ctx, flowID, flowState, user)
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
