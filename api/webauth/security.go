package webauth

import (
	"crypto/rand"
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
