package webauth

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/pilab-dev/shadow-sso/domain"
	"github.com/pilab-dev/shadow-sso/internal/audit"
	"github.com/pilab-dev/shadow-sso/internal/reqinfo"
	"github.com/pilab-dev/shadow-sso/internal/ssosession"
	"github.com/rs/zerolog/log"
)

func (wa *WebAuth) renderLoginPage(c *gin.Context, flowID string, providers []*domain.IdentityProvider, errMsg, email string) {
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
		"PageTitle":   "Sign In",
		"FlowID":      flowID,
		"CSRFToken":   csrfToken,
		"Providers":   providers,
		"BrandLogo":   wa.config.BrandLogoURL,
		"BrandName":   wa.config.BrandOrganizationName,
		"BrandColor":  wa.config.BrandPrimaryColor,
		"Error":       errMsg,
		"Email":       email,
		"HasAccounts": len(wa.loginAccounts(c.Request)) > 0,
	})
}

// renderAccountChooser shows the Google-style account switcher when the signed
// sso_session cookie contains one or more previously used accounts.
func (wa *WebAuth) renderAccountChooser(c *gin.Context, flowID, errMsg string) {
	accounts, _ := wa.accountChoices(c.Request)
	if len(accounts) == 0 {
		wa.renderLoginPage(c, flowID, nil, errMsg, c.Query("email"))
		return
	}

	csrfToken, err := generateCSRFToken()
	if err != nil {
		log.Error().Err(err).Msg("login: failed to generate CSRF token")
		c.HTML(http.StatusInternalServerError, "error.html", gin.H{
			"PageTitle": "Error",
			"Message":   "Internal error. Please try again.",
		})
		return
	}
	setCSRFCookie(c.Writer, csrfToken, 10*time.Minute, IsSecureRequest(c.Request))

	c.HTML(http.StatusOK, "account_chooser.html", gin.H{
		"PageTitle":  "Choose an account",
		"FlowID":     flowID,
		"CSRFToken":  csrfToken,
		"Accounts":   accounts,
		"BrandLogo":  wa.config.BrandLogoURL,
		"BrandName":  wa.brandName(c),
		"BrandColor": wa.config.BrandPrimaryColor,
		"Error":      errMsg,
		// Show the "Create account" link only when the realm allows self-registration.
		"RegistrationAllowed": wa.realmAllowsRegistration(c),
		"PasskeysEnabled":     wa.passkeysEnabled(),
	})
}

func (wa *WebAuth) realmAllowsRegistration(c *gin.Context) bool {
	s := wa.realm(c)
	return s != nil && s.RegistrationAllowed
}

func (wa *WebAuth) renderLoginStart(c *gin.Context, flowID string, providers []*domain.IdentityProvider, errMsg string) {
	if c.Query("form") == "1" || c.Query("new_account") != "" || errMsg != "" {
		wa.renderLoginPage(c, flowID, providers, errMsg, c.Query("email"))
		return
	}
	if accounts, _ := wa.accountChoices(c.Request); len(accounts) > 0 {
		wa.renderAccountChooser(c, flowID, errMsg)
		return
	}
	wa.renderLoginPage(c, flowID, providers, errMsg, c.Query("email"))
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

			providers, err := wa.idpRepo.ListIdPs(ctx, true)
			if err != nil {
				log.Error().Err(err).Msg("login: failed to load identity providers")
				providers = nil
			}
			wa.renderLoginStart(c, flowID, providers, "")
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

	// Load social providers only after the flow has been validated.
	providers, err := wa.idpRepo.ListIdPs(ctx, true)
	if err != nil {
		log.Error().Err(err).Msg("login: failed to load identity providers")
		providers = nil
	}

	errorMsg := c.Query("error")
	wa.renderLoginStart(c, flowID, providers, errorMsg)
}

// SelectAccountHandler handles the account chooser submission. Selecting the
// account that already owns a valid OP session completes the flow without a
// password; selecting any other account asks for the password (prefilled).
func (wa *WebAuth) SelectAccountHandler(c *gin.Context) {
	if !validateCSRFTokenForm(c) {
		c.HTML(http.StatusBadRequest, "error.html", gin.H{
			"PageTitle": "Error",
			"Message":   "Invalid form submission. Please try again.",
		})
		return
	}

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
		log.Warn().Err(err).Str("flow_id", flowID).Msg("account select: flow not found")
		c.HTML(http.StatusBadRequest, "error.html", gin.H{
			"PageTitle": "Error",
			"Message":   "Invalid or expired login request.",
		})
		return
	}
	if time.Now().After(flowState.ExpiresAt) {
		log.Warn().Str("flow_id", flowID).Msg("account select: flow expired")
		_ = wa.flowStore.DeleteFlow(ctx, flowID)
		c.HTML(http.StatusBadRequest, "error.html", gin.H{
			"PageTitle": "Error",
			"Message":   "Login request has expired. Please try again.",
		})
		return
	}

	userID := c.PostForm("user_id")
	var selected *ssosession.Account
	accounts := wa.loginAccounts(c.Request)
	for i := range accounts {
		if accounts[i].UserID == userID {
			selected = &accounts[i]
			break
		}
	}
	if selected == nil {
		c.Redirect(http.StatusFound, "/login?form=1&error="+url.QueryEscape("Account not found. Please sign in again."))
		return
	}

	requirePassword := promptRequiresLogin(flowState.Prompt)
	if !requirePassword {
		var activeSession *domain.UserSession

		// Prefer the account's own server-side OP session. This is what makes
		// switching between already signed-in accounts passwordless.
		if selected.OPSessionID != "" && wa.userSessionStore != nil {
			if session, sessionErr := wa.userSessionStore.GetUserSession(ctx, selected.OPSessionID); sessionErr == nil &&
				session != nil && session.UserID == selected.UserID {
				activeSession = session
			}
		}

		// Backward compatibility for accounts stored before per-account OP
		// session IDs were added.
		if activeSession == nil {
			if session, ok := wa.currentOPUserSession(c.Request); ok && session.UserID == selected.UserID {
				activeSession = session
				selected.OPSessionID = session.SessionID
			}
		}

		if activeSession != nil {
			authenticatedAt := activeSession.AuthenticatedAt
			if authenticatedAt.IsZero() {
				authenticatedAt = time.Now()
			}
			isSecure := IsSecureRequest(c.Request)
			ssosession.SetOPSessionCookie(c.Writer, activeSession.SessionID, isSecure)
			// The completion step owns the OP session for every other login
			// path; here the selected account already has one, so hand it over
			// instead of minting a second session for the same switch.
			c.Set(opSessionEstablishedKey, activeSession)

			flowState.UserID = selected.UserID
			flowState.UserAuthenticatedAt = authenticatedAt
			flowState.FlowID = flowID
			// finishLogin persists the flow (and runs the required-action
			// gate), so there is nothing to write here.

			session := wa.mergeLoginSession(c.Request, ssosession.Account{
				UserID:      selected.UserID,
				Email:       selected.Email,
				Name:        selected.Name,
				Picture:     selected.Picture,
				OPSessionID: activeSession.SessionID,
				LastUsed:    time.Now(),
			})
			if err := SetSSOSessionCookie(c.Writer, session, isSecure, wa.ssoCookieSecret); err != nil {
				log.Warn().Err(err).Msg("account select: failed to refresh SSO session cookie")
			}

			user, uErr := wa.userRepo.GetUserByID(ctx, selected.UserID)
			if uErr != nil || user.Status != domain.UserStatusActive {
				log.Warn().Err(uErr).Str("flow_id", flowID).Str("user_id", selected.UserID).Msg("account select: user not found or inactive")
				c.Redirect(http.StatusFound, "/login?new_account=1")
				return
			}

			log.Info().Str("flow_id", flowID).Str("user_id", selected.UserID).Msg("account select: continuing signed-in account")
			wa.finishLogin(c, ctx, flowID, flowState, user)
			return
		}
	}

	target := "/login?form=1"
	if selected.Email != "" {
		target += "&email=" + url.QueryEscape(selected.Email)
	}
	c.Redirect(http.StatusFound, target)
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
		wa.renderLoginPage(c, flowID, nil, "All fields are required.", email)
		return
	}

	rateLimitKey := c.ClientIP() + ":" + email
	if !wa.rateLimiter.Allow(rateLimitKey) {
		log.Warn().Str("email", email).Str("ip", c.ClientIP()).Msg("login: rate limited")
		wa.renderLoginPage(c, flowID, nil, "Too many attempts. Please try again later.", email)
		return
	}

	ctx := c.Request.Context()
	requestInfo := reqinfo.FromHTTP(c.Request)

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

	flowState.FlowID = flowID
	user, err := wa.userRepo.GetUserByEmail(ctx, email)
	if err != nil {
		wa.rateLimiter.RecordFailure(rateLimitKey)
		log.Warn().Err(err).Str("email", email).Msg("login: user not found")
		audit.Log("WebAuth", "Login", email, "", "user not found; "+requestInfo.Details(), false, err)
		wa.renderLoginPage(c, flowID, nil, "Invalid email or password.", email)
		return
	}

	if wa.accountLockedOut(ctx, user) {
		wa.rateLimiter.RecordFailure(rateLimitKey)
		log.Warn().Str("email", email).Str("user_id", user.ID).Msg("login: account locked out due to repeated failed attempts")
		audit.Log("WebAuth", "Login", user.ID, "", "account locked; "+requestInfo.Details(), false, errors.New("account locked"))
		wa.renderLoginPage(c, flowID, nil, "Account is temporarily locked. Please try again later.", email)
		return
	}

	requiresMFA, err := wa.runner.Authenticate(ctx, user, password)
	if err != nil {
		wa.rateLimiter.RecordFailure(rateLimitKey)
		wa.recordLoginFailure(ctx, user.ID)
		log.Warn().Str("email", email).Msg("login: password verification failed")
		audit.Log("WebAuth", "Login", user.ID, "", "password verification failed; "+requestInfo.Details(), false, err)
		wa.renderLoginPage(c, flowID, nil, "Invalid email or password.", email)
		return
	}

	if user.Status != domain.UserStatusActive {
		wa.rateLimiter.RecordFailure(rateLimitKey)
		wa.recordLoginFailure(ctx, user.ID)
		log.Warn().Str("email", email).Str("status", string(user.Status)).Msg("login: account not active")
		audit.Log("WebAuth", "Login", user.ID, "", "account not active ("+string(user.Status)+"); "+requestInfo.Details(), false, errors.New("account not active"))
		wa.renderLoginPage(c, flowID, nil, "Account is not active. Please contact support.", email)
		return
	}

	wa.rateLimiter.Reset(rateLimitKey)
	wa.resetLoginFailures(ctx, user.ID)

	// Enrollment enforcement: when MFA is required (per user, per realm, or by
	// the browser flow) and the account has no usable factor, send the user to
	// enrollment instead of completing the sign-in.
	enforced := requiresMFA || wa.mfaEnforced(ctx, user)
	if enforced && !hasUsableTOTP(user) {
		if hasUnverifiableActiveFactor(user) {
			// Never silently downgrade to a factor the login page cannot verify.
			log.Warn().Str("flow_id", flowID).Str("user_id", user.ID).Str("method", user.TwoFactorMethod).Msg("login: configured MFA method is not verifiable by the web login page")
			c.HTML(http.StatusForbidden, "error.html", gin.H{
				"PageTitle": "Second factor unavailable",
				"Message":   "This account has a second factor that the sign-in page cannot verify. Contact your administrator to reset it.",
			})
			return
		}
		flowState.UserID = user.ID
		flowState.UserAuthenticatedAt = time.Now()
		if err := wa.flowStore.UpdateFlow(ctx, flowID, flowState); err != nil {
			log.Error().Err(err).Str("flow_id", flowID).Msg("login: failed to update flow for MFA enrollment")
			c.HTML(http.StatusInternalServerError, "error.html", gin.H{
				"PageTitle": "Error",
				"Message":   "Internal error. Please try again.",
			})
			return
		}
		c.Redirect(http.StatusFound, "/mfa/enroll?flow_id="+url.QueryEscape(flowID))
		return
	}

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

// opSessionEstablished carries the server-side OP session a login path already
// created (account selection), so completeLogin reuses it instead of minting a
// second one for the same switch.
const opSessionEstablishedKey = "sso_op_session_established"

// redirectAfterAuthentication completes a login (password, MFA, or cached
// account selection) by sending the browser to consent, the return_to
// destination for flow-less logins, or back into the OIDC authorize step.
func (wa *WebAuth) redirectAfterAuthentication(c *gin.Context, ctx context.Context, flowID string, flowState *domain.LoginFlowState, isSecure bool) {
	c.Redirect(http.StatusFound, wa.afterAuthenticationURL(c, ctx, flowID, flowState, isSecure))
}

// afterAuthenticationURL returns where a completed login continues: consent, the signed return_to
// destination for flow-less logins, or back into the OIDC authorize step. It may clear the
// return_to cookie as a side effect.
func (wa *WebAuth) afterAuthenticationURL(c *gin.Context, ctx context.Context, flowID string, flowState *domain.LoginFlowState, isSecure bool) string {
	requiresConsent := false
	if flowState.ClientID != "" && wa.oauthService != nil {
		client, cErr := wa.oauthService.ValidateClient(ctx, flowState.ClientID, "")
		if cErr == nil && client != nil && client.RequireConsent {
			requiresConsent = true
		}
	}
	if requiresConsent {
		return "/consent?flow_id=" + url.QueryEscape(flowID)
	}
	if flowState.ClientID == "" {
		// Flow-less login (no OIDC client): complete by redirecting to the
		// signed return_to destination captured when the synthetic flow began.
		// The cookie is cleared on use; fall back to "/" when absent or invalid.
		rt := readReturnToCookie(c.Request, wa.ssoCookieSecret)
		clearReturnToCookie(c.Writer, isSecure)
		if rt != "" && validReturnTo(rt) {
			return rt
		}
		return "/"
	}
	return "/oauth2/authorize?flow_id=" + url.QueryEscape(flowID)
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
// mfaEnforced reports whether a user must complete a second factor at login,
// combining the per-user flag with the realm-wide policy.
func (wa *WebAuth) mfaEnforced(ctx context.Context, user *domain.User) bool {
	if user == nil {
		return false
	}
	if user.MFARequired {
		return true
	}
	if wa.realmSettingsRepo == nil {
		return false
	}
	settings, err := wa.realmSettingsRepo.GetRealmSettings(ctx)
	if err != nil || settings == nil {
		return false
	}
	return settings.RequireMFA
}

// hasUsableTOTP reports whether the server-rendered login page can verify a
// TOTP code for this user. It is the only second factor the /mfa page supports.
func hasUsableTOTP(user *domain.User) bool {
	return user != nil &&
		user.IsTwoFactorEnabled &&
		user.TwoFactorMethod == "TOTP" &&
		user.TwoFactorSecret != ""
}

// hasUnverifiableActiveFactor reports whether the account has an enabled
// second factor that the /mfa page cannot verify. Such accounts must not be
// routed to enrollment, because that would replace their existing factor with
// a weaker path.
func hasUnverifiableActiveFactor(user *domain.User) bool {
	if user == nil {
		return false
	}
	if user.IsTwoFactorEnabled && user.TwoFactorSecret == "" {
		return true
	}
	if user.IsTwoFactorEnabled && user.TwoFactorMethod != "" && user.TwoFactorMethod != "NONE" && user.TwoFactorMethod != "TOTP" {
		return true
	}
	if user.EmailMFAEnabled || user.PushMFAEnabled {
		return true
	}
	for _, m := range user.MfaMethods {
		if m.Verified && m.Type != domain.MfaMethodTypeTOTP {
			return true
		}
	}
	return false
}

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
