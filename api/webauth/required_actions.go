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
	// Submit processes the form. done=true means the action is complete and user
	// has been persisted by the handler; otherwise errMsg is re-rendered.
	Submit(c *gin.Context, wa *WebAuth, user *domain.User) (done bool, errMsg string, err error)
}

// requiredActionHandlers is the registry of implemented actions. Pending actions
// without a handler are skipped (and logged) instead of locking the user out.
var requiredActionHandlers = map[string]requiredActionHandler{
	domain.RequiredActionUpdatePassword: updatePasswordAction{},
}

func supportsRequiredAction(alias string) bool {
	_, ok := requiredActionHandlers[alias]
	return ok
}

// finishLogin is the single completion point for every successful login
// (password, MFA, account selection, completed required action). If the user
// still has a supported required action pending it parks the flow on that action
// WITHOUT issuing the SSO cookie; otherwise it clears the pending marker, issues
// the SSO session cookie and continues to consent / authorization.
func (wa *WebAuth) finishLogin(c *gin.Context, ctx context.Context, flowID string, flowState *domain.LoginFlowState, user *domain.User) {
	flowState.UserID = user.ID
	if flowState.UserAuthenticatedAt.IsZero() {
		flowState.UserAuthenticatedAt = time.Now()
	}

	next, skipped := authflow.NextRequiredAction(user, supportsRequiredAction)
	if len(skipped) > 0 {
		log.Warn().Str("user_id", user.ID).Strs("actions", skipped).Msg("login: pending required actions have no handler yet; skipping")
	}

	if next != "" {
		flowState.Pending = domain.FlowPendingActionPrefix + next
		if err := wa.flowStore.UpdateFlow(ctx, flowID, flowState); err != nil {
			log.Error().Err(err).Str("flow_id", flowID).Msg("login: failed to park flow on required action")
			wa.renderInternalError(c, "Internal error. Please try again.")
			return
		}
		c.Redirect(http.StatusFound, "/required-action?flow_id="+url.QueryEscape(flowID))
		return
	}

	flowState.Pending = ""
	if err := wa.flowStore.UpdateFlow(ctx, flowID, flowState); err != nil {
		log.Error().Err(err).Str("flow_id", flowID).Msg("login: failed to update flow state after auth")
		wa.renderInternalError(c, "Internal error. Please try again.")
		return
	}

	displayName := user.Email
	if user.FirstName != "" || user.LastName != "" {
		displayName = user.FirstName + " " + user.LastName
	}
	isSecure := IsSecureRequest(c.Request)
	session := mergeSessionAccount(c.Request, wa.ssoCookieSecret, ssosession.Account{
		UserID:   user.ID,
		Email:    user.Email,
		Name:     displayName,
		LastUsed: time.Now(),
	})
	if err := SetSSOSessionCookie(c.Writer, session, isSecure, wa.ssoCookieSecret); err != nil {
		log.Error().Err(err).Msg("login: failed to set SSO session cookie")
		wa.renderInternalError(c, "Failed to create session. Please try again.")
		return
	}

	wa.redirectAfterAuthentication(c, ctx, flowID, flowState, isSecure)
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
	if !ok {
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
	_, user, handler, _, ok := wa.loadRequiredActionFlow(c, flowID)
	if !ok {
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

	done, errMsg, err := handler.Submit(c, wa, user)
	if err != nil {
		log.Error().Err(err).Str("flow_id", flowID).Str("action", alias).Msg("required action: submit failed")
		wa.renderInternalError(c, "Could not complete this step. Please try again.")
		return
	}
	if !done {
		handler.Render(c, wa, flowID, user, errMsg)
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
		"BrandName": wa.config.BrandOrganizationName,
	})
}

// updatePasswordAction implements UPDATE_PASSWORD.
type updatePasswordAction struct{}

func (updatePasswordAction) Render(c *gin.Context, wa *WebAuth, flowID string, _ *domain.User, errMsg string) {
	wa.renderRequiredActionPage(c, "update_password.html", "Update password", flowID, errMsg)
}

func (updatePasswordAction) Submit(c *gin.Context, wa *WebAuth, user *domain.User) (bool, string, error) {
	newPassword := c.PostForm("new_password")
	if newPassword != c.PostForm("confirm_password") {
		return false, "The passwords do not match.", nil
	}
	if err := pkgauth.ValidatePassword(newPassword, wa.passwordPolicy(c.Request.Context())); err != nil {
		return false, err.Error(), nil
	}
	if wa.passwordHasher.Verify(user.PasswordHash, newPassword) == nil {
		return false, "The new password must be different from the current one.", nil
	}
	hash, err := wa.passwordHasher.Hash(newPassword)
	if err != nil {
		return false, "", err
	}
	user.PasswordHash = hash
	return true, "", nil
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
