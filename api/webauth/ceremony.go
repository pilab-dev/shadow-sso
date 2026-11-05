package webauth

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
)

// A WebAuthn ceremony (registration or login) spans two requests; the server-side challenge state
// (webauthn.SessionData) travels between them in an HMAC-signed, short-lived, HttpOnly cookie. This
// keeps the state across restarts and replicas without a store, and the signature makes it
// tamper-proof; the challenge itself is not secret (the browser receives it too).
//
// The cookie is cleared when a ceremony finishes but, being stateless, cannot be revoked server-side:
// within its 5-minute lifetime a captured response could be replayed. That is neutralised at the
// use sites — registration refuses an already-registered credential ID, login refuses a flow that is
// already authenticated, and a non-increasing signature counter is rejected as a possible clone.

const (
	ceremonyCookieName = "sso_webauthn"
	ceremonyTTL        = 5 * time.Minute

	ceremonyRegister = "register"
	ceremonyLogin    = "login"
)

type ceremonyState struct {
	Kind    string               `json:"k"`
	UserID  string               `json:"u,omitempty"`
	FlowID  string               `json:"f,omitempty"`
	Name    string               `json:"n,omitempty"`
	Session webauthn.SessionData `json:"s"`
	Expires time.Time            `json:"e"`
}

var errBadCeremony = errors.New("invalid or expired passkey ceremony")

func signCeremony(st ceremonyState, secret string) (string, error) {
	st.Expires = time.Now().Add(ceremonyTTL)
	payload, err := json.Marshal(st)
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	return base64.RawURLEncoding.EncodeToString(payload) + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), nil
}

func verifyCeremony(value, secret, kind string) (*ceremonyState, error) {
	parts := strings.Split(value, ".")
	if secret == "" || len(parts) != 2 {
		return nil, errBadCeremony
	}
	payload, err1 := base64.RawURLEncoding.DecodeString(parts[0])
	sig, err2 := base64.RawURLEncoding.DecodeString(parts[1])
	if err1 != nil || err2 != nil {
		return nil, errBadCeremony
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	if subtle.ConstantTimeCompare(sig, mac.Sum(nil)) != 1 {
		return nil, errBadCeremony
	}
	var st ceremonyState
	if err := json.Unmarshal(payload, &st); err != nil || st.Kind != kind || time.Now().After(st.Expires) {
		return nil, errBadCeremony
	}
	return &st, nil
}

func setCeremonyCookie(w http.ResponseWriter, st ceremonyState, secret string, secure bool) error {
	v, err := signCeremony(st, secret)
	if err != nil {
		return err
	}
	http.SetCookie(w, &http.Cookie{
		Name: ceremonyCookieName, Value: v, Path: "/", MaxAge: int(ceremonyTTL.Seconds()),
		HttpOnly: true, Secure: secure, SameSite: http.SameSiteLaxMode,
	})
	return nil
}

func clearCeremonyCookie(w http.ResponseWriter, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name: ceremonyCookieName, Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, Secure: secure, SameSite: http.SameSiteLaxMode,
	})
}

// readCeremony returns the verified ceremony of the given kind from the request cookie. The cookie
// is cleared by callers once the ceremony finishes (successfully or not).
func readCeremony(r *http.Request, secret, kind string) (*ceremonyState, error) {
	c, err := r.Cookie(ceremonyCookieName)
	if err != nil || c.Value == "" {
		return nil, errBadCeremony
	}
	return verifyCeremony(c.Value, secret, kind)
}
