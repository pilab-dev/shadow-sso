package webauth

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	"github.com/pilab-dev/shadow-sso/domain"
	"github.com/rs/zerolog/log"
)

// NewWebAuthn builds the relying party from the public issuer URL (RP ID = host, origin = scheme://host[:port]).
func NewWebAuthn(issuerURL, displayName string) (*webauthn.WebAuthn, error) {
	u, err := url.Parse(issuerURL)
	if err != nil || u.Host == "" || u.Hostname() == "" {
		return nil, errors.New("webauthn: issuer URL must be an absolute URL")
	}
	return webauthn.New(&webauthn.Config{
		RPDisplayName: displayName,
		RPID:          u.Hostname(),
		RPOrigins:     []string{u.Scheme + "://" + u.Host},
	})
}

// webAuthnUser adapts domain.User to webauthn.User.
type webAuthnUser struct {
	user  *domain.User
	creds []webauthn.Credential
}

func newWebAuthnUser(u *domain.User) *webAuthnUser {
	w := &webAuthnUser{user: u}
	for _, d := range u.WebAuthnDevices {
		if d.CredentialJSON == "" {
			continue // legacy record without a usable credential
		}
		var cred webauthn.Credential
		if err := json.Unmarshal([]byte(d.CredentialJSON), &cred); err == nil {
			w.creds = append(w.creds, cred)
		}
	}
	return w
}

func (w *webAuthnUser) WebAuthnID() []byte                         { return []byte(w.user.ID) }
func (w *webAuthnUser) WebAuthnName() string                       { return w.user.Email }
func (w *webAuthnUser) WebAuthnDisplayName() string                { return displayName(w.user) }
func (w *webAuthnUser) WebAuthnCredentials() []webauthn.Credential { return w.creds }

func credentialID(cred *webauthn.Credential) string {
	return base64.RawURLEncoding.EncodeToString(cred.ID)
}

// passkeyDevice converts a freshly registered credential to its stored form.
func passkeyDevice(name string, cred *webauthn.Credential) (domain.WebAuthnDevice, error) {
	raw, err := json.Marshal(cred)
	if err != nil {
		return domain.WebAuthnDevice{}, err
	}
	transports := make([]string, 0, len(cred.Transport))
	for _, t := range cred.Transport {
		transports = append(transports, string(t))
	}
	if name == "" {
		name = "Passkey"
	}
	return domain.WebAuthnDevice{
		ID:             uuid.NewString(),
		Name:           name,
		CredentialID:   credentialID(cred),
		PublicKey:      base64.RawURLEncoding.EncodeToString(cred.PublicKey),
		Counter:        int32(cred.Authenticator.SignCount),
		CreatedAt:      time.Now().UTC(),
		Transports:     transports,
		CredentialJSON: string(raw),
	}, nil
}

// passkeysEnabled reports whether the relying party is configured.
func (wa *WebAuth) passkeysEnabled() bool { return wa.webAuthn != nil }

// validateCSRFHeader is the fetch/JSON counterpart of validateCSRFTokenForm: the double-submit
// cookie must equal the X-CSRF-Token header.
func validateCSRFHeader(c *gin.Context) bool {
	cookieVal, err := c.Cookie(CSRFCookieName)
	if err != nil || cookieVal == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(cookieVal), []byte(c.GetHeader("X-CSRF-Token"))) == 1
}

func jsonError(c *gin.Context, status int, msg string) {
	c.Header("Cache-Control", "no-store")
	c.JSON(status, gin.H{"error": msg})
}

// StaticAssetHandler serves the embedded browser scripts (CSP only allows scripts from 'self').
func (wa *WebAuth) StaticAssetHandler(c *gin.Context) {
	name := c.Param("name")
	if name != "webauthn.js" {
		c.Status(http.StatusNotFound)
		return
	}
	data, err := staticFS.ReadFile("static/" + name)
	if err != nil {
		c.Status(http.StatusNotFound)
		return
	}
	c.Header("Cache-Control", "public, max-age=3600")
	c.Data(http.StatusOK, "text/javascript; charset=utf-8", data)
}

// ---- registration (account console) ---------------------------------------------------------

type passkeyView struct {
	ID        string
	Name      string
	CreatedAt time.Time
}

// AccountPasskeysPageHandler serves GET /account/passkeys.
func (wa *WebAuth) AccountPasskeysPageHandler() gin.HandlerFunc {
	return wa.requireAccount(func(c *gin.Context, user *domain.User) {
		var views []passkeyView
		for _, d := range user.WebAuthnDevices {
			if d.CredentialJSON != "" {
				views = append(views, passkeyView{ID: d.ID, Name: d.Name, CreatedAt: d.CreatedAt})
			}
		}
		wa.renderAccount(c, "account_passkeys.html", "Passkeys", "passkeys", user, gin.H{
			"Passkeys": views, "Available": wa.passkeysEnabled(),
			"CanConfirm":  user.PasswordHash != "" || (user.IsTwoFactorEnabled && user.TwoFactorMethod == "TOTP"),
			"HasPassword": user.PasswordHash != "",
		})
	})
}

// PasskeyRegisterBeginHandler serves POST /account/passkeys/register/begin (form: current_password, name).
func (wa *WebAuth) PasskeyRegisterBeginHandler() gin.HandlerFunc {
	return wa.requireAccount(func(c *gin.Context, user *domain.User) {
		if !wa.passkeysEnabled() {
			jsonError(c, http.StatusNotFound, "Passkeys are not available.")
			return
		}
		if !validateCSRFHeader(c) {
			jsonError(c, http.StatusBadRequest, "Invalid request. Reload the page and try again.")
			return
		}
		if !wa.confirmIdentity(c, user) {
			jsonError(c, http.StatusForbidden, "The current password is incorrect.")
			return
		}
		wu := newWebAuthnUser(user)
		exclusions := make([]protocol.CredentialDescriptor, 0, len(wu.creds))
		for i := range wu.creds {
			exclusions = append(exclusions, wu.creds[i].Descriptor())
		}
		creation, session, err := wa.webAuthn.BeginRegistration(wu,
			webauthn.WithAuthenticatorSelection(protocol.AuthenticatorSelection{
				RequireResidentKey: protocol.ResidentKeyRequired(),
				ResidentKey:        protocol.ResidentKeyRequirementRequired,
				UserVerification:   protocol.VerificationRequired,
			}),
			webauthn.WithExclusions(exclusions),
		)
		if err != nil {
			log.Error().Err(err).Str("user_id", user.ID).Msg("passkey: begin registration failed")
			jsonError(c, http.StatusInternalServerError, "Could not start passkey registration.")
			return
		}
		name := strings.TrimSpace(c.PostForm("name"))
		if len(name) > 60 {
			name = name[:60]
		}
		if err := setCeremonyCookie(c.Writer, ceremonyState{Kind: ceremonyRegister, UserID: user.ID, Name: name, Session: *session},
			wa.ssoCookieSecret, IsSecureRequest(c.Request)); err != nil {
			jsonError(c, http.StatusInternalServerError, "Could not start passkey registration.")
			return
		}
		c.Header("Cache-Control", "no-store")
		c.JSON(http.StatusOK, creation)
	})
}

// PasskeyRegisterFinishHandler serves POST /account/passkeys/register/finish (JSON credential).
func (wa *WebAuth) PasskeyRegisterFinishHandler() gin.HandlerFunc {
	return wa.requireAccount(func(c *gin.Context, user *domain.User) {
		if !wa.passkeysEnabled() {
			jsonError(c, http.StatusNotFound, "Passkeys are not available.")
			return
		}
		secure := IsSecureRequest(c.Request)
		defer clearCeremonyCookie(c.Writer, secure) // single use, success or not
		if !validateCSRFHeader(c) {
			jsonError(c, http.StatusBadRequest, "Invalid request. Reload the page and try again.")
			return
		}
		st, err := readCeremony(c.Request, wa.ssoCookieSecret, ceremonyRegister)
		if err != nil || st.UserID != user.ID {
			jsonError(c, http.StatusBadRequest, "The passkey request expired. Please try again.")
			return
		}
		cred, err := wa.webAuthn.FinishRegistration(newWebAuthnUser(user), st.Session, c.Request)
		if err != nil {
			log.Warn().Err(err).Str("user_id", user.ID).Msg("passkey: registration verification failed")
			jsonError(c, http.StatusBadRequest, "The passkey could not be verified.")
			return
		}
		device, err := passkeyDevice(st.Name, cred)
		// The signed ceremony cookie is stateless, so the same registration response could be
		// replayed within its 5-minute window; a credential ID can only be added once.
		for _, d := range user.WebAuthnDevices {
			if err == nil && d.CredentialID == device.CredentialID {
				jsonError(c, http.StatusBadRequest, "This passkey is already registered.")
				return
			}
		}
		if err != nil {
			jsonError(c, http.StatusInternalServerError, "Could not save the passkey.")
			return
		}
		if err := wa.userRepo.AddWebAuthnDevice(c.Request.Context(), user.ID, &device); err != nil {
			log.Error().Err(err).Str("user_id", user.ID).Msg("passkey: saving device failed")
			jsonError(c, http.StatusInternalServerError, "Could not save the passkey.")
			return
		}
		log.Info().Str("user_id", user.ID).Str("device_id", device.ID).Msg("passkey registered")
		c.Header("Cache-Control", "no-store")
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})
}

// PasskeyDeleteSubmitHandler serves POST /account/passkeys/delete (form: device_id, current_password).
func (wa *WebAuth) PasskeyDeleteSubmitHandler() gin.HandlerFunc {
	return wa.accountPost(func(c *gin.Context, user *domain.User) {
		if !wa.confirmIdentity(c, user) {
			wa.renderAccount(c, "account_passkeys.html", "Passkeys", "passkeys", user, gin.H{
				"Error": "The current password is incorrect.", "Available": wa.passkeysEnabled(),
				"CanConfirm": true, "HasPassword": user.PasswordHash != "", "Passkeys": passkeyViews(user),
			})
			return
		}
		deviceID := c.PostForm("device_id")
		owned := false
		for _, d := range user.WebAuthnDevices {
			if d.ID == deviceID {
				owned = true
			}
		}
		if owned {
			if err := wa.userRepo.RemoveWebAuthnDevice(c.Request.Context(), user.ID, deviceID); err != nil {
				log.Warn().Err(err).Str("user_id", user.ID).Msg("passkey: removal failed")
			}
		}
		wa.accountRedirect(c, "/account/passkeys", "passkey_removed")
	})
}

func passkeyViews(user *domain.User) []passkeyView {
	var views []passkeyView
	for _, d := range user.WebAuthnDevices {
		if d.CredentialJSON != "" {
			views = append(views, passkeyView{ID: d.ID, Name: d.Name, CreatedAt: d.CreatedAt})
		}
	}
	return views
}

// ---- login ----------------------------------------------------------------------------------

// PasskeyLoginBeginHandler serves POST /login/passkey/begin: a discoverable (username-less) assertion.
func (wa *WebAuth) PasskeyLoginBeginHandler(c *gin.Context) {
	if !wa.passkeysEnabled() {
		jsonError(c, http.StatusNotFound, "Passkeys are not available.")
		return
	}
	if !validateCSRFHeader(c) {
		jsonError(c, http.StatusBadRequest, "Invalid request. Reload the page and try again.")
		return
	}
	flowID := GetFlowIDFromCookie(c.Request)
	if _, ok := wa.liveFlow(c.Request.Context(), flowID); !ok {
		jsonError(c, http.StatusBadRequest, "Your sign-in request expired. Please start again.")
		return
	}
	key := "passkey:" + c.ClientIP()
	if !wa.rateLimiter.Allow(key) {
		jsonError(c, http.StatusTooManyRequests, "Too many attempts. Please try again later.")
		return
	}
	assertion, session, err := wa.webAuthn.BeginDiscoverableLogin(webauthn.WithUserVerification(protocol.VerificationRequired))
	if err != nil {
		log.Error().Err(err).Msg("passkey: begin login failed")
		jsonError(c, http.StatusInternalServerError, "Could not start passkey sign-in.")
		return
	}
	if err := setCeremonyCookie(c.Writer, ceremonyState{Kind: ceremonyLogin, FlowID: flowID, Session: *session},
		wa.ssoCookieSecret, IsSecureRequest(c.Request)); err != nil {
		jsonError(c, http.StatusInternalServerError, "Could not start passkey sign-in.")
		return
	}
	c.Header("Cache-Control", "no-store")
	c.JSON(http.StatusOK, assertion)
}

// PasskeyLoginFinishHandler serves POST /login/passkey/finish (JSON assertion). A verified passkey
// (user verification is required) satisfies password AND second factor; required actions still run.
func (wa *WebAuth) PasskeyLoginFinishHandler(c *gin.Context) {
	if !wa.passkeysEnabled() {
		jsonError(c, http.StatusNotFound, "Passkeys are not available.")
		return
	}
	secure := IsSecureRequest(c.Request)
	defer clearCeremonyCookie(c.Writer, secure) // single use, success or not
	if !validateCSRFHeader(c) {
		jsonError(c, http.StatusBadRequest, "Invalid request. Reload the page and try again.")
		return
	}
	ctx := c.Request.Context()
	st, err := readCeremony(c.Request, wa.ssoCookieSecret, ceremonyLogin)
	flowID := GetFlowIDFromCookie(c.Request)
	if err != nil || st.FlowID == "" || st.FlowID != flowID {
		jsonError(c, http.StatusBadRequest, "The passkey request expired. Please try again.")
		return
	}
	flowState, ok := wa.liveFlow(ctx, flowID)
	if !ok {
		jsonError(c, http.StatusBadRequest, "Your sign-in request expired. Please start again.")
		return
	}
	// Replay guard: a flow that already holds an authenticated user cannot be completed again
	// with a captured assertion (the ceremony cookie itself is stateless, see ceremony.go).
	if flowState.UserID != "" {
		jsonError(c, http.StatusBadRequest, "This sign-in request was already completed. Please start again.")
		return
	}
	key := "passkey:" + c.ClientIP()
	if !wa.rateLimiter.Allow(key) {
		jsonError(c, http.StatusTooManyRequests, "Too many attempts. Please try again later.")
		return
	}

	var loaded *domain.User
	handler := func(rawID, userHandle []byte) (webauthn.User, error) {
		u, err := wa.userRepo.GetUserByID(ctx, string(userHandle))
		if err != nil || u == nil || u.Status != domain.UserStatusActive {
			return nil, errors.New("unknown user")
		}
		loaded = u
		return newWebAuthnUser(u), nil
	}
	_, cred, err := wa.webAuthn.FinishPasskeyLogin(handler, st.Session, c.Request)
	if err != nil || loaded == nil || cred == nil {
		wa.rateLimiter.RecordFailure(key)
		log.Warn().Err(err).Msg("passkey: login verification failed")
		jsonError(c, http.StatusUnauthorized, "Passkey sign-in failed.")
		return
	}
	if cred.Authenticator.CloneWarning {
		wa.rateLimiter.RecordFailure(key)
		log.Warn().Str("user_id", loaded.ID).Msg("passkey: possible cloned authenticator; rejecting")
		jsonError(c, http.StatusUnauthorized, "Passkey sign-in failed.")
		return
	}
	if wa.accountLockedOut(ctx, loaded) {
		jsonError(c, http.StatusForbidden, "Account is temporarily locked. Please try again later.")
		return
	}

	// Persist the updated sign counter / flags.
	if raw, err := json.Marshal(cred); err == nil {
		id := credentialID(cred)
		for i := range loaded.WebAuthnDevices {
			if loaded.WebAuthnDevices[i].CredentialID == id {
				loaded.WebAuthnDevices[i].CredentialJSON = string(raw)
				loaded.WebAuthnDevices[i].Counter = int32(cred.Authenticator.SignCount)
			}
		}
		if err := wa.userRepo.UpdateUser(ctx, loaded); err != nil {
			log.Warn().Err(err).Str("user_id", loaded.ID).Msg("passkey: persisting sign counter failed")
		}
	}

	wa.rateLimiter.Reset(key)
	flowState.AMR = domain.AddAMR(nil, domain.AMRHardware)
	next, failure := wa.completeLogin(c, ctx, flowID, flowState, loaded)
	if failure != "" {
		jsonError(c, http.StatusInternalServerError, failure)
		return
	}
	log.Info().Str("user_id", loaded.ID).Msg("passkey sign-in")
	c.Header("Cache-Control", "no-store")
	c.JSON(http.StatusOK, gin.H{"next": next})
}

// liveFlow returns the stored login flow if it exists and has not expired.
func (wa *WebAuth) liveFlow(ctx context.Context, flowID string) (*domain.LoginFlowState, bool) {
	if flowID == "" {
		return nil, false
	}
	st, err := wa.flowStore.GetFlow(ctx, flowID)
	if err != nil || st == nil || time.Now().After(st.ExpiresAt) {
		return nil, false
	}
	return st, true
}
