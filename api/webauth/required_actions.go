package webauth

import (
	"context"
	"net/http"
	"net/url"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/pilab-dev/shadow-sso/domain"
	"github.com/pilab-dev/shadow-sso/internal/authflow"
	"github.com/pilab-dev/shadow-sso/internal/ssosession"
	pkgauth "github.com/pilab-dev/shadow-sso/pkg/auth"
	"github.com/rs/zerolog/log"
)

// requiredActionHandler renders and processes one Keycloak-style required action.
// Handlers run after every authentication step (password, MFA) has succeeded and
// before the SSO session cookie is issued or an authorization code is generated.
type requiredActionHandler interface {
	// Render shows the action's form; errMsg is a user-facing validation message.
	Render(c *gin.Context, wa *WebAuth, flowID string, user *domain.User, errMsg string)
	// Submit processes the form and reports what to do next.
	Submit(c *gin.Context, wa *WebAuth, user *domain.User) (actionResult, error)
}

// actionResult is the outcome of requiredActionHandler.Submit.
type actionResult struct {
	// Done: the action is complete; the framework removes it from the user,
	// persists the user and continues the login.
	Done bool
	// Err: validation message; the action's form is re-rendered with it.
	Err string
	// Rendered: the handler already wrote the response (e.g. an interstitial
	// page). The framework does nothing further for this request.
	Rendered bool
}

// requiredActionHandlers is the registry of implemented actions. Pending actions
// without a handler are skipped (and logged) instead of locking the user out.
var requiredActionHandlers = map[string]requiredActionHandler{
	domain.RequiredActionUpdatePassword: updatePasswordAction{},
	domain.RequiredActionConfigureTOTP:  configureTOTPAction{},
	domain.RequiredActionVerifyEmail:    verifyEmailAction{},
}

// actionSatisfied reports whether a pending action no longer needs doing (the user
// already has the thing it would collect), so it can be dropped silently.
func actionSatisfied(user *domain.User, alias string) bool {
	switch alias {
	case domain.RequiredActionConfigureTOTP:
		return user.IsTwoFactorEnabled || user.EmailMFAEnabled || user.PushMFAEnabled
	case domain.RequiredActionVerifyEmail:
		return user.IsEmailVerified
	}
	return false
}

// pruneSatisfiedActions removes already-satisfied actions from user and reports whether it changed anything.
func pruneSatisfiedActions(user *domain.User) bool {
	changed := false
	for _, alias := range append([]string(nil), user.RequiredActions...) {
		if actionSatisfied(user, alias) {
			user.RemoveRequiredAction(alias)
			changed = true
		}
	}
	return changed
}

// supportsRequiredAction reports whether alias can be completed right now. VERIFY_EMAIL needs a
// mail provider; without one it is skipped (and logged) rather than locking the user out.
func (wa *WebAuth) supportsRequiredAction(alias string) bool {
	if _, ok := requiredActionHandlers[alias]; !ok {
		return false
	}
	if alias == domain.RequiredActionVerifyEmail && wa.emailService == nil {
		return false
	}
	return true
}

// finishLogin is the single completion point for every successful login
// (password, MFA, passkey, account selection, completed required action). If the user
// still has a supported required action pending it parks the flow on that action
// WITHOUT issuing the SSO cookie; otherwise it clears the pending marker, issues
// the SSO session cookie and continues to consent / authorization.
func (wa *WebAuth) finishLogin(c *gin.Context, ctx context.Context, flowID string, flowState *domain.LoginFlowState, user *domain.User) {
	next, failure := wa.completeLogin(c, ctx, flowID, flowState, user)
	if failure != "" {
		wa.renderInternalError(c, failure)
		return
	}
	c.Redirect(http.StatusFound, next)
}

// completeLogin performs finishLogin's work and returns the URL to continue at instead of
// redirecting, so JSON endpoints (passkey login) can hand it to the browser. A non-empty
// failure is a user-facing message for an internal error.
func (wa *WebAuth) completeLogin(c *gin.Context, ctx context.Context, flowID string, flowState *domain.LoginFlowState, user *domain.User) (next, failure string) {
	flowState.UserID = user.ID
	if flowState.UserAuthenticatedAt.IsZero() {
		flowState.UserAuthenticatedAt = time.Now()
	}

	if pruneSatisfiedActions(user) {
		if err := wa.userRepo.UpdateUser(ctx, user); err != nil {
			log.Warn().Err(err).Str("user_id", user.ID).Msg("login: failed to persist pruned required actions")
		}
	}
	action, skipped := authflow.NextRequiredAction(user, wa.supportsRequiredAction)
	if len(skipped) > 0 {
		log.Warn().Str("user_id", user.ID).Strs("actions", skipped).Msg("login: pending required actions have no handler yet; skipping")
	}

	if action != "" {
		flowState.Pending = domain.FlowPendingActionPrefix + action
		if err := wa.flowStore.UpdateFlow(ctx, flowID, flowState); err != nil {
			log.Error().Err(err).Str("flow_id", flowID).Msg("login: failed to park flow on required action")
			return "", "Internal error. Please try again."
		}
		return "/required-action?flow_id=" + url.QueryEscape(flowID), ""
	}

	flowState.Pending = ""
	if err := wa.flowStore.UpdateFlow(ctx, flowID, flowState); err != nil {
		log.Error().Err(err).Str("flow_id", flowID).Msg("login: failed to update flow state after auth")
		return "", "Internal error. Please try again."
	}

	// Establish the server-side OP session first so other OIDC clients
	// recognize this login without redirecting the user back to the form.
	// Account selection already established one for the account it picked.
	var opSession *domain.UserSession
	if carried, ok := c.Get(opSessionEstablishedKey); ok {
		opSession, _ = carried.(*domain.UserSession)
	}
	if opSession == nil || opSession.UserID != user.ID {
		established, err := wa.establishOPSession(c, user.ID)
		if err != nil {
			log.Error().Err(err).Str("user_id", user.ID).Msg("login: failed to establish OP session")
			return "", "Failed to create session. Please try again."
		}
		opSession = established
	}
	opSessionID := ""
	if opSession != nil {
		opSessionID = opSession.SessionID
	}

	displayName := user.Email
	if user.FirstName != "" || user.LastName != "" {
		displayName = user.FirstName + " " + user.LastName
	}
	isSecure := IsSecureRequest(c.Request)
	session := mergeSessionAccount(c.Request, wa.ssoCookieSecret, ssosession.Account{
		UserID:      user.ID,
		Email:       user.Email,
		Name:        displayName,
		OPSessionID: opSessionID,
		LastUsed:    time.Now(),
	})
	if err := SetSSOSessionCookie(c.Writer, session, isSecure, wa.ssoCookieSecret); err != nil {
		log.Error().Err(err).Msg("login: failed to set SSO session cookie")
		return "", "Failed to create session. Please try again."
	}

	return wa.afterAuthenticationURL(c, ctx, flowID, flowState, isSecure), ""
}

func (wa *WebAuth) renderInternalError(c *gin.Context, msg string) {
	c.HTML(http.StatusInternalServerError, "error.html", gin.H{"PageTitle": "Error", "Message": msg})
}

// loadRequiredActionFlow validates the flow behind a /required-action request and
// returns the flow, the authenticated user and the pending handler. It writes the
// error response itself and returns ok=false when the request must stop.
func (wa *WebAuth) loadRequiredActionFlow(c *gin.Context, flowID string) (*domain.LoginFlowState, *domain.User, requiredActionHandler, string, bool) {
	ctx := c.Request.Context()
	fail := func(status int, msg string) (*domain.LoginFlowState, *domain.User, requiredActionHandler, string, bool) {
		c.HTML(status, "error.html", gin.H{"PageTitle": "Error", "Message": msg})
		return nil, nil, nil, "", false
	}
	if flowID == "" {
		return fail(http.StatusBadRequest, "Invalid or expired login request. Please try again.")
	}
	flowState, err := wa.flowStore.GetFlow(ctx, flowID)
	if err != nil || flowState == nil || time.Now().After(flowState.ExpiresAt) {
		return fail(http.StatusBadRequest, "Invalid or expired login request. Please try again.")
	}
	// Only a flow that finished password AND MFA is ever parked on an action.
	alias := flowState.PendingAction()
	if flowState.UserID == "" || alias == "" {
		return fail(http.StatusBadRequest, "Invalid or expired login request. Please try again.")
	}
	handler, ok := requiredActionHandlers[alias]
	if !ok || !wa.supportsRequiredAction(alias) {
		return fail(http.StatusBadRequest, "This step is not available. Please contact support.")
	}
	user, err := wa.userRepo.GetUserByID(ctx, flowState.UserID)
	if err != nil || user == nil || user.Status != domain.UserStatusActive {
		return fail(http.StatusBadRequest, "Invalid or expired login request. Please try again.")
	}
	return flowState, user, handler, alias, true
}

// RequiredActionPageHandler serves GET /required-action.
func (wa *WebAuth) RequiredActionPageHandler(c *gin.Context) {
	flowID := c.Query("flow_id")
	flowState, user, handler, alias, ok := wa.loadRequiredActionFlow(c, flowID)
	if !ok {
		return
	}
	// The action may have been completed out of band (e.g. the verification link was opened
	// in another tab): carry on with the login instead of showing a stale form.
	if !user.HasRequiredAction(alias) || actionSatisfied(user, alias) {
		wa.finishLogin(c, c.Request.Context(), flowID, flowState, user)
		return
	}
	handler.Render(c, wa, flowID, user, "")
}

// RequiredActionSubmitHandler serves POST /required-action.
func (wa *WebAuth) RequiredActionSubmitHandler(c *gin.Context) {
	if !validateCSRFTokenForm(c) {
		c.HTML(http.StatusBadRequest, "error.html", gin.H{
			"PageTitle": "Error",
			"Message":   "Invalid form submission. Please try again.",
		})
		return
	}
	flowID := c.PostForm("flow_id")
	flowState, user, handler, alias, ok := wa.loadRequiredActionFlow(c, flowID)
	if !ok {
		return
	}
	ctx := c.Request.Context()

	// "continue" is posted by interstitial pages (e.g. recovery codes) after the action was
	// already completed and persisted.
	if c.PostForm("continue") == "1" && (!user.HasRequiredAction(alias) || actionSatisfied(user, alias)) {
		wa.finishLogin(c, ctx, flowID, flowState, user)
		return
	}

	res, err := handler.Submit(c, wa, user)
	if err != nil {
		log.Error().Err(err).Str("flow_id", flowID).Str("action", alias).Msg("required action: submit failed")
		wa.renderInternalError(c, "Could not complete this step. Please try again.")
		return
	}
	if res.Rendered {
		return
	}
	if !res.Done {
		handler.Render(c, wa, flowID, user, res.Err)
		return
	}

	user.RemoveRequiredAction(alias)
	if err := wa.userRepo.UpdateUser(ctx, user); err != nil {
		log.Error().Err(err).Str("flow_id", flowID).Msg("required action: failed to persist user")
		wa.renderInternalError(c, "Could not complete this step. Please try again.")
		return
	}
	log.Info().Str("user_id", user.ID).Str("action", alias).Msg("required action completed")

	// Re-enter the completion point: it either parks on the next action or finishes the login.
	wa.finishLogin(c, ctx, flowID, flowState, user)
}

// renderRequiredActionPage renders a required-action template with a fresh CSRF token.
func (wa *WebAuth) renderRequiredActionPage(c *gin.Context, tmpl, title, flowID, errMsg string) {
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
	c.HTML(status, tmpl, gin.H{
		"PageTitle": title,
		"FlowID":    flowID,
		"CSRFToken": csrfToken,
		"Error":     errMsg,
		"BrandName": wa.brandName(c),
	})
}

// updatePasswordAction implements UPDATE_PASSWORD.
type updatePasswordAction struct{}

func (updatePasswordAction) Render(c *gin.Context, wa *WebAuth, flowID string, _ *domain.User, errMsg string) {
	wa.renderRequiredActionPage(c, "update_password.html", "Update password", flowID, errMsg)
}

func (updatePasswordAction) Submit(c *gin.Context, wa *WebAuth, user *domain.User) (actionResult, error) {
	newPassword := c.PostForm("new_password")
	if newPassword != c.PostForm("confirm_password") {
		return actionResult{Err: "The passwords do not match."}, nil
	}
	if err := pkgauth.ValidatePassword(newPassword, wa.passwordPolicy(c.Request.Context())); err != nil {
		return actionResult{Err: err.Error()}, nil
	}
	if wa.passwordHasher.Verify(user.PasswordHash, newPassword) == nil {
		return actionResult{Err: "The new password must be different from the current one."}, nil
	}
	hash, err := wa.passwordHasher.Hash(newPassword)
	if err != nil {
		return actionResult{}, err
	}
	user.PasswordHash = hash
	return actionResult{Done: true}, nil
}

// passwordPolicy resolves the realm password policy, falling back to a minimum length of 8.
func (wa *WebAuth) passwordPolicy(ctx context.Context) pkgauth.PasswordPolicy {
	fallback := pkgauth.PasswordPolicy{MinLength: 8}
	if wa.realmSettingsRepo == nil {
		return fallback
	}
	settings, err := wa.realmSettingsRepo.GetRealmSettings(ctx)
	if err != nil || settings == nil {
		return fallback
	}
	policy := pkgauth.PasswordPolicyFromRealm(settings)
	if policy.MinLength == 0 {
		policy.MinLength = 8
	}
	return policy
}
