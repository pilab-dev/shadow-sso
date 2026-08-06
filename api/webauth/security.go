package webauth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/pilab-dev/shadow-sso/internal/ssosession"
)

const (
	// CSRFCookieName is the name of the cookie used for CSRF protection.
	CSRFCookieName = "sso_csrf_token"
	// CSRFHeaderName is the name of the HTTP header carrying the CSRF token.
	CSRFHeaderName = "X-CSRF-Token"
	// FlowCookieName is the name of the cookie carrying the server-side flow ID.
	// The client never sees this value — it is only read from the cookie.
	FlowCookieName = "sso_oidc_flow_id"
	// ReturnToCookieName is the name of the signed cookie carrying the
	// validated same-origin destination for flow-less logins. The return_to
	// value travels in this cookie (HMAC-signed), never in a form field.
	ReturnToCookieName = "sso_return_to"
	// syntheticFlowLifetime is the expiry of synthetic (ClientID-less) login
	// flows and their sso_oidc_flow_id / sso_return_to cookies.
	syntheticFlowLifetime = 15 * time.Minute
)

// ---------------------------------------------------------------------------
// Rate Limiter
// ---------------------------------------------------------------------------

type rateLimitEntry struct {
	attempts     int
	lockedUntil time.Time
}

// RateLimiter provides in-memory brute-force protection keyed by IP+username.
type RateLimiter struct {
	mu              sync.Mutex
	entries         map[string]*rateLimitEntry
	maxAttempts     int
	lockoutDuration time.Duration
}

// NewRateLimiter creates a RateLimiter that locks a key after maxAttempts
// failures for lockoutDuration.
func NewRateLimiter(maxAttempts int, lockoutDuration time.Duration) *RateLimiter {
	return &RateLimiter{
		entries:         make(map[string]*rateLimitEntry),
		maxAttempts:     maxAttempts,
		lockoutDuration: lockoutDuration,
	}
}

// Allow reports whether the request for key should be permitted.
func (rl *RateLimiter) Allow(key string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	entry, exists := rl.entries[key]
	if !exists {
		return true
	}

	if !entry.lockedUntil.IsZero() && time.Now().Before(entry.lockedUntil) {
		return false
	}

	// Lockout expired; reset the entry.
	if !entry.lockedUntil.IsZero() && time.Now().After(entry.lockedUntil) {
		entry.attempts = 0
		entry.lockedUntil = time.Time{}
	}

	return true
}

// RecordFailure increments the failure counter and locks the key when the
// threshold is reached.
func (rl *RateLimiter) RecordFailure(key string) {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	entry, exists := rl.entries[key]
	if !exists {
		entry = &rateLimitEntry{}
		rl.entries[key] = entry
	}

	entry.attempts++
	if entry.attempts >= rl.maxAttempts {
		entry.lockedUntil = time.Now().Add(rl.lockoutDuration)
	}
}

// Reset clears the counter for key (called on successful authentication).
func (rl *RateLimiter) Reset(key string) {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	delete(rl.entries, key)
}

// ---------------------------------------------------------------------------
// CSRF helpers
// ---------------------------------------------------------------------------

// generateCSRFToken creates a cryptographically random hex-encoded CSRF token.
func generateCSRFToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate CSRF token: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// setCSRFCookie sets an HttpOnly, Secure, SameSite=Strict CSRF cookie.
func setCSRFCookie(w http.ResponseWriter, token string, maxAge time.Duration, isSecure bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     CSRFCookieName,
		Value:    token,
		Path:     "/",
		MaxAge:   int(maxAge.Seconds()),
		HttpOnly: true,
		Secure:   isSecure,
		SameSite: http.SameSiteStrictMode,
	})
}

// ---------------------------------------------------------------------------
// SSO Session cookie helpers
// ---------------------------------------------------------------------------

// SetSSOSessionCookie signs and sets the sso_session cookie on the response.
func SetSSOSessionCookie(w http.ResponseWriter, session *ssosession.Session, isSecure bool, secret string) error {
	return ssosession.SetCookie(w, session, isSecure, secret)
}

// GetSSOSession reads and verifies the sso_session cookie from the request.
func GetSSOSession(r *http.Request, secret string) (*ssosession.Session, error) {
	cookie, err := r.Cookie(ssosession.CookieName)
	if err != nil {
		return nil, err
	}
	return ssosession.VerifyAndDecode(cookie.Value, secret)
}

// ClearSSOSession immediately expires the sso_session cookie.
func ClearSSOSession(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     ssosession.CookieName,
		Value:    "",
		Domain:   ssosession.CookieDomain,
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
}

// IsSecureRequest checks whether the incoming request was served over TLS
// (directly or via a trusted reverse proxy).
func IsSecureRequest(r *http.Request) bool {
	return r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
}

// GetFlowIDFromCookie extracts the flow ID from the sso_oidc_flow_id cookie.
// Returns empty string if the cookie is missing or empty.
func GetFlowIDFromCookie(r *http.Request) string {
	cookie, err := r.Cookie(FlowCookieName)
	if err != nil || cookie.Value == "" {
		return ""
	}
	return cookie.Value
}

// ---------------------------------------------------------------------------
// Flow-less login (return_to) helpers
// ---------------------------------------------------------------------------

// validReturnTo guards against open redirects: only same-origin, root-relative
// paths are accepted. Absolute URLs (http/https), protocol-relative URLs (//),
// backslash escapes, and dot-segment traversal (/../) are rejected.
func validReturnTo(rt string) bool {
	return strings.HasPrefix(rt, "/") &&
		!strings.HasPrefix(rt, "//") &&
		!strings.Contains(rt, "\\") &&
		!strings.HasPrefix(rt, "http://") &&
		!strings.HasPrefix(rt, "https://") &&
		!strings.Contains(rt, "/../")
}

// setFlowCookie sets the sso_oidc_flow_id cookie with the same attributes the
// OIDC authorize flow uses, so GetFlowIDFromCookie reads it back.
func setFlowCookie(w http.ResponseWriter, flowID string, isSecure bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     FlowCookieName,
		Value:    flowID,
		Path:     "/",
		MaxAge:   int(syntheticFlowLifetime.Seconds()),
		HttpOnly: true,
		Secure:   isSecure,
		SameSite: http.SameSiteLaxMode,
	})
}

// setReturnToCookie signs the return_to value with the cookie signing secret
// (HMAC-SHA256 over the raw value, base64url payload.signature — the same
// scheme the sso_session cookie uses) and stores it in an HttpOnly,
// SameSite=Lax cookie.
func setReturnToCookie(w http.ResponseWriter, returnTo string, isSecure bool, secret string) {
	payload := base64.RawURLEncoding.EncodeToString([]byte(returnTo))
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(returnTo))
	signature := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	http.SetCookie(w, &http.Cookie{
		Name:     ReturnToCookieName,
		Value:    payload + "." + signature,
		Path:     "/",
		MaxAge:   int(syntheticFlowLifetime.Seconds()),
		HttpOnly: true,
		Secure:   isSecure,
		SameSite: http.SameSiteLaxMode,
	})
}

// readReturnToCookie verifies the signature of the sso_return_to cookie and
// returns the return_to value, or "" when the cookie is missing, malformed,
// or the signature does not verify.
func readReturnToCookie(r *http.Request, secret string) string {
	cookie, err := r.Cookie(ReturnToCookieName)
	if err != nil || cookie.Value == "" {
		return ""
	}

	dotIdx := strings.LastIndexByte(cookie.Value, '.')
	if dotIdx <= 0 || dotIdx == len(cookie.Value)-1 {
		return ""
	}
	payload, err := base64.RawURLEncoding.DecodeString(cookie.Value[:dotIdx])
	if err != nil {
		return ""
	}
	signature, err := base64.RawURLEncoding.DecodeString(cookie.Value[dotIdx+1:])
	if err != nil {
		return ""
	}

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	if subtle.ConstantTimeCompare(signature, mac.Sum(nil)) != 1 {
		return ""
	}
	return string(payload)
}

// clearReturnToCookie immediately expires the sso_return_to cookie. It is
// called after the destination has been consumed on login completion.
func clearReturnToCookie(w http.ResponseWriter, isSecure bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     ReturnToCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   isSecure,
		SameSite: http.SameSiteLaxMode,
	})
}
