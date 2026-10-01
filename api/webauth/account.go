package webauth

import (
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/pilab-dev/shadow-sso/domain"
	"github.com/pilab-dev/shadow-sso/internal/auth/totp"
	pkgauth "github.com/pilab-dev/shadow-sso/pkg/auth"
	"github.com/rs/zerolog/log"
)

// Account console: server-rendered self-service pages under /account, authenticated by the
// signed sso_session cookie. Sensitive changes (password, MFA) additionally require the user
// to re-enter their current password (or a valid TOTP code) — the step-up check.

// accountMessages maps the whitelisted ?ok= codes to flash text (never reflect arbitrary input).
var accountMessages = map[string]string{
	"profile_saved":    "Your profile was updated.",
	"password_changed": "Your password was changed.",
	"mfa_disabled":     "Two-factor authentication was turned off.",
	"session_revoked":  "The session was signed out.",
	"identity_removed": "The linked account was removed.",
}

// accountHandler is an account page handler that receives the authenticated user.
type accountHandler func(c *gin.Context, user *domain.User)

// requireAccount resolves the signed-in user from the sso_session cookie (most recently used
// account) or redirects to the login page, returning here afterwards.
func (wa *WebAuth) requireAccount(next accountHandler) gin.HandlerFunc {
	return func(c *gin.Context) {
		returnTo := "/account"
		if c.Request.Method == http.MethodGet {
			if rt := c.Request.URL.RequestURI(); validReturnTo(rt) {
				returnTo = rt
			}
		}
		loginURL := "/login?return_to=" + url.QueryEscape(returnTo)

		session, err := GetSSOSession(c.Request, wa.ssoCookieSecret)
		if err != nil || session == nil || len(session.Accounts) == 0 {
			c.Redirect(http.StatusFound, loginURL)
			return
		}
		accounts := append(session.Accounts[:0:0], session.Accounts...)
		sort.SliceStable(accounts, func(i, j int) bool { return accounts[i].LastUsed.After(accounts[j].LastUsed) })

		user, err := wa.userRepo.GetUserByID(c.Request.Context(), accounts[0].UserID)
		if err != nil || user == nil || user.Status != domain.UserStatusActive {
			c.Redirect(http.StatusFound, loginURL)
			return
		}
		c.Header("Cache-Control", "no-store")
		next(c, user)
	}
}

// accountPost wraps a POST handler with the CSRF check.
func (wa *WebAuth) accountPost(next accountHandler) gin.HandlerFunc {
	return wa.requireAccount(func(c *gin.Context, user *domain.User) {
		if !validateCSRFTokenForm(c) {
			wa.renderMessage(c, http.StatusBadRequest, "Error", "Invalid form submission. Please try again.", "/account", "Back to your account")
			return
		}
		next(c, user)
	})
}

func (wa *WebAuth) renderAccount(c *gin.Context, tmpl, title, active string, user *domain.User, data gin.H) {
	data["Active"] = active
	data["User"] = user
	data["Email"] = user.Email
	if _, ok := data["Flash"]; !ok {
		data["Flash"] = accountMessages[c.Query("ok")]
	}
	wa.renderPage(c, tmpl, title, data)
}

func (wa *WebAuth) accountRedirect(c *gin.Context, path, ok string) {
	if ok != "" {
		path += "?ok=" + url.QueryEscape(ok)
	}
	c.Redirect(http.StatusSeeOther, path)
}

// confirmIdentity is the step-up check: the current password, or a valid TOTP code for users that
// have TOTP enabled (and for social-only users without a password).
func (wa *WebAuth) confirmIdentity(c *gin.Context, user *domain.User) bool {
	key := "account-confirm:" + user.ID
	if !wa.rateLimiter.Allow(key) {
		return false
	}
	secret := c.PostForm("current_password")
	ok := user.PasswordHash != "" && secret != "" && wa.passwordHasher.Verify(user.PasswordHash, secret) == nil
	if !ok && user.IsTwoFactorEnabled && user.TwoFactorMethod == "TOTP" && user.TwoFactorSecret != "" {
		ok, _ = totp.ValidateTOTPCode(user.TwoFactorSecret, secret)
	}
	if !ok {
		wa.rateLimiter.RecordFailure(key)
		return false
	}
	wa.rateLimiter.Reset(key)
	return true
}

// ---- overview / profile ---------------------------------------------------------------------

// AccountOverviewHandler serves GET /account.
func (wa *WebAuth) AccountOverviewHandler() gin.HandlerFunc {
	return wa.requireAccount(func(c *gin.Context, user *domain.User) {
		wa.renderAccount(c, "account_overview.html", "My account", "overview", user, gin.H{
			"FirstName": user.FirstName, "LastName": user.LastName,
		})
	})
}

// AccountProfileSubmitHandler serves POST /account/profile.
func (wa *WebAuth) AccountProfileSubmitHandler() gin.HandlerFunc {
	return wa.accountPost(func(c *gin.Context, user *domain.User) {
		first := strings.TrimSpace(c.PostForm("first_name"))
		last := strings.TrimSpace(c.PostForm("last_name"))
		if len(first) > 100 || len(last) > 100 {
			wa.renderAccount(c, "account_overview.html", "My account", "overview", user, gin.H{
				"Error": "Names must be 100 characters or fewer.", "FirstName": first, "LastName": last,
			})
			return
		}
		user.FirstName, user.LastName = first, last
		if err := wa.userRepo.UpdateUser(c.Request.Context(), user); err != nil {
			log.Error().Err(err).Str("user_id", user.ID).Msg("account: profile update failed")
			wa.renderInternalError(c, "Could not save your profile. Please try again.")
			return
		}
		wa.accountRedirect(c, "/account", "profile_saved")
	})
}

// ---- security: password and MFA -------------------------------------------------------------

// AccountSecurityHandler serves GET /account/security.
func (wa *WebAuth) AccountSecurityHandler() gin.HandlerFunc {
	return wa.requireAccount(func(c *gin.Context, user *domain.User) {
		wa.renderAccount(c, "account_security.html", "Security", "security", user, gin.H{
			"HasPassword": user.PasswordHash != "",
			"TOTPEnabled": user.IsTwoFactorEnabled && user.TwoFactorMethod == "TOTP",
			"MFAEnabled":  user.IsTwoFactorEnabled || user.EmailMFAEnabled || user.PushMFAEnabled,
		})
	})
}

func (wa *WebAuth) renderSecurityError(c *gin.Context, user *domain.User, msg string) {
	wa.renderAccount(c, "account_security.html", "Security", "security", user, gin.H{
		"Error":       msg,
		"HasPassword": user.PasswordHash != "",
		"TOTPEnabled": user.IsTwoFactorEnabled && user.TwoFactorMethod == "TOTP",
		"MFAEnabled":  user.IsTwoFactorEnabled || user.EmailMFAEnabled || user.PushMFAEnabled,
	})
}

// AccountPasswordSubmitHandler serves POST /account/password.
func (wa *WebAuth) AccountPasswordSubmitHandler() gin.HandlerFunc {
	return wa.accountPost(func(c *gin.Context, user *domain.User) {
		ctx := c.Request.Context()
		// Users that have a password must prove they know it (or hold their TOTP device).
		if user.PasswordHash != "" && !wa.confirmIdentity(c, user) {
			wa.renderSecurityError(c, user, "The current password is incorrect.")
			return
		}
		newPassword := c.PostForm("new_password")
		if newPassword != c.PostForm("confirm_password") {
			wa.renderSecurityError(c, user, "The new passwords do not match.")
			return
		}
		if err := pkgauth.ValidatePassword(newPassword, wa.passwordPolicy(ctx)); err != nil {
			wa.renderSecurityError(c, user, err.Error())
			return
		}
		if user.PasswordHash != "" && wa.passwordHasher.Verify(user.PasswordHash, newPassword) == nil {
			wa.renderSecurityError(c, user, "The new password must be different from the current one.")
			return
		}
		hash, err := wa.passwordHasher.Hash(newPassword)
		if err != nil {
			wa.renderInternalError(c, "Could not change your password. Please try again.")
			return
		}
		user.PasswordHash = hash
		user.RemoveRequiredAction(domain.RequiredActionUpdatePassword)
		if err := wa.userRepo.UpdateUser(ctx, user); err != nil {
			log.Error().Err(err).Str("user_id", user.ID).Msg("account: password change failed")
			wa.renderInternalError(c, "Could not change your password. Please try again.")
			return
		}
		// Sign out every other OAuth session: whoever knew the old password must not keep access.
		if wa.sessionRepo != nil {
			if _, err := wa.sessionRepo.DeleteSessionsByUserID(ctx, user.ID); err != nil {
				log.Warn().Err(err).Str("user_id", user.ID).Msg("account: failed to revoke sessions after password change")
			}
		}
		log.Info().Str("user_id", user.ID).Msg("account: password changed")
		wa.accountRedirect(c, "/account/security", "password_changed")
	})
}

// AccountTOTPPageHandler serves GET /account/mfa/totp (authenticator enrolment).
func (wa *WebAuth) AccountTOTPPageHandler() gin.HandlerFunc {
	return wa.requireAccount(func(c *gin.Context, user *domain.User) {
		if user.IsTwoFactorEnabled {
			wa.accountRedirect(c, "/account/security", "")
			return
		}
		qr, secret, ok := wa.prepareTOTP(c, user)
		if !ok {
			return
		}
		wa.renderPage(c, "totp_setup.html", "Set up authenticator", gin.H{
			"QRCode": qr, "Secret": secret, "Action": "/account/mfa/totp",
		})
	})
}

// AccountTOTPSubmitHandler serves POST /account/mfa/totp.
func (wa *WebAuth) AccountTOTPSubmitHandler() gin.HandlerFunc {
	return wa.accountPost(func(c *gin.Context, user *domain.User) {
		codes, errMsg, err := wa.enableTOTP(c, user)
		if err != nil {
			log.Error().Err(err).Str("user_id", user.ID).Msg("account: enabling TOTP failed")
			wa.renderInternalError(c, "Could not enable two-factor authentication. Please try again.")
			return
		}
		if errMsg != "" {
			qr, secret, ok := wa.prepareTOTP(c, user)
			if !ok {
				return
			}
			wa.renderPage(c, "totp_setup.html", "Set up authenticator", gin.H{
				"QRCode": qr, "Secret": secret, "Action": "/account/mfa/totp", "Error": errMsg,
			})
			return
		}
		user.RemoveRequiredAction(domain.RequiredActionConfigureTOTP)
		if err := wa.userRepo.UpdateUser(c.Request.Context(), user); err != nil {
			wa.renderInternalError(c, "Could not enable two-factor authentication. Please try again.")
			return
		}
		wa.renderPage(c, "recovery_codes.html", "Save your recovery codes", gin.H{
			"Codes": codes, "ContinueHref": "/account/security",
		})
	})
}

// AccountRecoveryCodesSubmitHandler serves POST /account/mfa/recovery: issue a fresh set of codes.
func (wa *WebAuth) AccountRecoveryCodesSubmitHandler() gin.HandlerFunc {
	return wa.accountPost(func(c *gin.Context, user *domain.User) {
		if !user.IsTwoFactorEnabled {
			wa.accountRedirect(c, "/account/security", "")
			return
		}
		if !wa.confirmIdentity(c, user) {
			wa.renderSecurityError(c, user, "The current password is incorrect.")
			return
		}
		plain, hashed, err := totp.GenerateRecoveryCodes(totp.DefaultNumRecoveryCodes, totp.DefaultRecoveryCodeLength)
		if err != nil {
			wa.renderInternalError(c, "Could not generate recovery codes. Please try again.")
			return
		}
		user.TwoFactorRecoveryCodes = hashed
		if err := wa.userRepo.UpdateUser(c.Request.Context(), user); err != nil {
			wa.renderInternalError(c, "Could not generate recovery codes. Please try again.")
			return
		}
		wa.renderPage(c, "recovery_codes.html", "Save your recovery codes", gin.H{
			"Codes": plain, "ContinueHref": "/account/security",
		})
	})
}

// AccountMFADisableSubmitHandler serves POST /account/mfa/disable.
func (wa *WebAuth) AccountMFADisableSubmitHandler() gin.HandlerFunc {
	return wa.accountPost(func(c *gin.Context, user *domain.User) {
		if !wa.confirmIdentity(c, user) {
			wa.renderSecurityError(c, user, "The current password is incorrect.")
			return
		}
		user.IsTwoFactorEnabled = false
		user.TwoFactorMethod = "NONE"
		user.TwoFactorSecret = ""
		user.TwoFactorRecoveryCodes = []string{}
		if err := wa.userRepo.UpdateUser(c.Request.Context(), user); err != nil {
			wa.renderInternalError(c, "Could not turn off two-factor authentication. Please try again.")
			return
		}
		log.Info().Str("user_id", user.ID).Msg("account: TOTP disabled")
		wa.accountRedirect(c, "/account/security", "mfa_disabled")
	})
}

// ---- sessions -------------------------------------------------------------------------------

type accountSessionView struct {
	ID         string
	ClientID   string
	IPAddress  string
	UserAgent  string
	LastUsedAt time.Time
	CreatedAt  time.Time
}

// AccountSessionsHandler serves GET /account/sessions.
func (wa *WebAuth) AccountSessionsHandler() gin.HandlerFunc {
	return wa.requireAccount(func(c *gin.Context, user *domain.User) {
		var views []accountSessionView
		if wa.sessionRepo != nil {
			notRevoked := false
			sessions, err := wa.sessionRepo.ListSessionsByUserID(c.Request.Context(), user.ID, domain.SessionFilter{IsRevoked: &notRevoked})
			if err != nil {
				log.Warn().Err(err).Str("user_id", user.ID).Msg("account: listing sessions failed")
			}
			for _, s := range sessions {
				if s.IsRevoked || (!s.ExpiresAt.IsZero() && time.Now().After(s.ExpiresAt)) {
					continue
				}
				views = append(views, accountSessionView{ID: s.ID, ClientID: s.ClientID, IPAddress: s.IPAddress,
					UserAgent: s.UserAgent, LastUsedAt: s.LastUsedAt, CreatedAt: s.CreatedAt})
			}
			sort.SliceStable(views, func(i, j int) bool { return views[i].LastUsedAt.After(views[j].LastUsedAt) })
		}
		wa.renderAccount(c, "account_sessions.html", "Device activity", "sessions", user, gin.H{
			"Sessions": views, "Available": wa.sessionRepo != nil,
		})
	})
}

// AccountSessionRevokeHandler serves POST /account/sessions/revoke.
func (wa *WebAuth) AccountSessionRevokeHandler() gin.HandlerFunc {
	return wa.accountPost(func(c *gin.Context, user *domain.User) {
		ctx := c.Request.Context()
		if wa.sessionRepo == nil {
			wa.accountRedirect(c, "/account/sessions", "")
			return
		}
		id := c.PostForm("session_id")
		session, err := wa.sessionRepo.GetSessionByID(ctx, id)
		// Only the owner may revoke; answer identically for unknown and foreign IDs.
		if err == nil && session != nil && session.UserID == user.ID {
			if err := wa.sessionRepo.DeleteSession(ctx, session.ID); err != nil {
				log.Warn().Err(err).Str("user_id", user.ID).Msg("account: revoking session failed")
			}
		}
		wa.accountRedirect(c, "/account/sessions", "session_revoked")
	})
}

// ---- linked accounts ------------------------------------------------------------------------

type accountIdentityView struct {
	Provider       string
	ProviderUserID string
	Email          string
}

// AccountLinkedHandler serves GET /account/linked.
func (wa *WebAuth) AccountLinkedHandler() gin.HandlerFunc {
	return wa.requireAccount(func(c *gin.Context, user *domain.User) {
		views, canUnlink := wa.linkedIdentities(c, user)
		wa.renderAccount(c, "account_linked.html", "Linked accounts", "linked", user, gin.H{
			"Identities": views, "CanUnlink": canUnlink, "Available": wa.federationService != nil,
		})
	})
}

// linkedIdentities lists the user's federated identities. Unlinking is only offered when the
// user can still sign in afterwards (a password, or another linked identity).
func (wa *WebAuth) linkedIdentities(c *gin.Context, user *domain.User) ([]accountIdentityView, bool) {
	if wa.federationService == nil {
		return nil, false
	}
	ctx := c.Request.Context()
	idents, err := wa.federationService.ListUserFederatedIdentities(ctx, user.ID)
	if err != nil {
		log.Warn().Err(err).Str("user_id", user.ID).Msg("account: listing federated identities failed")
		return nil, false
	}
	providers := map[string]string{}
	if wa.idpRepo != nil {
		if idps, err := wa.idpRepo.ListIdPs(ctx, false); err == nil {
			for _, p := range idps {
				providers[p.ID] = p.Name
			}
		}
	}
	var views []accountIdentityView
	for _, i := range idents {
		name := providers[i.ProviderID]
		if name == "" {
			name = i.ProviderID
		}
		views = append(views, accountIdentityView{Provider: name, ProviderUserID: i.ProviderUserID, Email: i.ProviderEmail})
	}
	return views, user.PasswordHash != "" || len(views) > 1
}

// AccountUnlinkSubmitHandler serves POST /account/linked/unlink.
func (wa *WebAuth) AccountUnlinkSubmitHandler() gin.HandlerFunc {
	return wa.accountPost(func(c *gin.Context, user *domain.User) {
		if wa.federationService == nil {
			wa.accountRedirect(c, "/account/linked", "")
			return
		}
		if _, canUnlink := wa.linkedIdentities(c, user); !canUnlink {
			views, _ := wa.linkedIdentities(c, user)
			wa.renderAccount(c, "account_linked.html", "Linked accounts", "linked", user, gin.H{
				"Identities": views, "CanUnlink": false, "Available": true,
				"Error": "Set a password before removing your only sign-in method.",
			})
			return
		}
		provider, providerUserID := c.PostForm("provider"), c.PostForm("provider_user_id")
		if err := wa.federationService.RemoveUserFederatedIdentity(c.Request.Context(), user.ID, provider, providerUserID); err != nil {
			log.Warn().Err(err).Str("user_id", user.ID).Msg("account: unlink failed")
		}
		wa.accountRedirect(c, "/account/linked", "identity_removed")
	})
}

// AccountLogoutSubmitHandler serves POST /account/logout: forget the browser's SSO session.
func (wa *WebAuth) AccountLogoutSubmitHandler() gin.HandlerFunc {
	return wa.accountPost(func(c *gin.Context, user *domain.User) {
		ClearSSOSession(c.Writer)
		c.Redirect(http.StatusSeeOther, "/login")
	})
}
