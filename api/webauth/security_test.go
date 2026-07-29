package webauth

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// RateLimiter
// ---------------------------------------------------------------------------

func TestRateLimiter_Allow_InitiallyTrue(t *testing.T) {
	rl := NewRateLimiter(5, 15*time.Minute)
	assert.True(t, rl.Allow("test-key"))
}

func TestRateLimiter_BlockedAfterMaxAttempts(t *testing.T) {
	rl := NewRateLimiter(3, 15*time.Minute)
	for i := 0; i < 3; i++ {
		rl.RecordFailure("test-key")
	}
	// 3 failures == maxAttempts (3), should be locked
	assert.False(t, rl.Allow("test-key"))
}

func TestRateLimiter_ResetClearsFailures(t *testing.T) {
	rl := NewRateLimiter(3, 15*time.Minute)
	rl.RecordFailure("test-key")
	rl.RecordFailure("test-key")
	rl.Reset("test-key")
	assert.True(t, rl.Allow("test-key"))
}

func TestRateLimiter_LockoutExpires(t *testing.T) {
	rl := NewRateLimiter(2, 1*time.Millisecond) // 1ms lockout
	rl.RecordFailure("test-key")
	rl.RecordFailure("test-key") // locked now
	assert.False(t, rl.Allow("test-key"))

	time.Sleep(5 * time.Millisecond)
	assert.True(t, rl.Allow("test-key"))
}

func TestRateLimiter_DifferentKeysAreIndependent(t *testing.T) {
	rl := NewRateLimiter(2, 15*time.Minute)
	rl.RecordFailure("key1")
	rl.RecordFailure("key1") // key1 locked
	assert.False(t, rl.Allow("key1"))
	assert.True(t, rl.Allow("key2"))
}

// ---------------------------------------------------------------------------
// CSRF
// ---------------------------------------------------------------------------

func TestGenerateCSRFToken_NonEmpty(t *testing.T) {
	token, err := generateCSRFToken()
	require.NoError(t, err)
	assert.NotEmpty(t, token)
}

func TestGenerateCSRFToken_Unique(t *testing.T) {
	t1, err := generateCSRFToken()
	require.NoError(t, err)
	t2, err := generateCSRFToken()
	require.NoError(t, err)
	assert.NotEqual(t, t1, t2)
}

func TestGenerateCSRFToken_Length(t *testing.T) {
	// 32 random bytes → 64 hex chars
	token, err := generateCSRFToken()
	require.NoError(t, err)
	assert.Len(t, token, 64)
}

func TestIsSecureRequest_WithTLS(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.TLS = &tls.ConnectionState{}
	assert.True(t, IsSecureRequest(req))
}

func TestIsSecureRequest_WithoutTLS(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	assert.False(t, IsSecureRequest(req))
}

func TestIsSecureRequest_ForwardedProto(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-Forwarded-Proto", "https")
	assert.True(t, IsSecureRequest(req))
}

// ---------------------------------------------------------------------------
// Cookie helpers
// ---------------------------------------------------------------------------

func TestSetCSRFCookie_SetsCookie(t *testing.T) {
	w := httptest.NewRecorder()
	setCSRFCookie(w, "tok123", 30*time.Minute, true)

	cookies := w.Result().Cookies()
	require.Len(t, cookies, 1)

	c := cookies[0]
	assert.Equal(t, CSRFCookieName, c.Name)
	assert.Equal(t, "tok123", c.Value)
	assert.Equal(t, "/", c.Path)
	assert.True(t, c.HttpOnly)
	assert.True(t, c.Secure)
	assert.Equal(t, http.SameSiteStrictMode, c.SameSite)
	assert.Equal(t, 1800, c.MaxAge)
}

func TestSetCSRFCookie_Insecure(t *testing.T) {
	w := httptest.NewRecorder()
	setCSRFCookie(w, "tok456", 10*time.Minute, false)

	cookies := w.Result().Cookies()
	require.Len(t, cookies, 1)
	assert.False(t, cookies[0].Secure)
}

func TestCSRFCookieNameConstant(t *testing.T) {
	assert.Equal(t, "sso_csrf_token", CSRFCookieName)
}
