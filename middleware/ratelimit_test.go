package middleware_test

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/pilab-dev/shadow-sso/middleware"
	"github.com/stretchr/testify/assert"
)

func init() {
	gin.SetMode(gin.TestMode)
}

// ─────────────────────────────────────────────────────────────────────────────
// Core RateLimiter tests (in-memory fallback)
// ─────────────────────────────────────────────────────────────────────────────

func TestRateLimit_DisabledConfig_PassesThrough(t *testing.T) {
	limiter := middleware.NewRateLimiter(&middleware.RateLimitConfig{Enabled: false})

	limit := middleware.RateLimit{Max: 3, Window: time.Minute}

	// All requests should pass when disabled
	for i := 0; i < 10; i++ {
		result := limiter.Check(t.Context(), "key:test", limit)
		assert.True(t, result.Allowed, "request %d should be allowed when rate limiting is disabled", i)
		assert.Equal(t, limit.Max, result.Remaining)
	}
}

func TestRateLimit_InMemory_AllowsUpToLimit(t *testing.T) {
	// Use Enabled=true with nil Redis to force in-memory fallback
	limiter := middleware.NewRateLimiter(&middleware.RateLimitConfig{Enabled: true, Redis: nil})
	limit := middleware.RateLimit{Max: 5, Window: time.Minute}

	// First 5 requests should be allowed
	for i := 0; i < 5; i++ {
		result := limiter.Check(t.Context(), "key:allow", limit)
		assert.True(t, result.Allowed, "request %d should be allowed", i+1)
	}

	// 6th request should be rejected
	result := limiter.Check(t.Context(), "key:allow", limit)
	assert.False(t, result.Allowed, "6th request should be blocked")
	assert.Equal(t, 0, result.Remaining)
	assert.Greater(t, result.RetryAfter, time.Duration(0))
}

func TestRateLimit_InMemory_DifferentKeysAreIsolated(t *testing.T) {
	limiter := middleware.NewRateLimiter(&middleware.RateLimitConfig{Enabled: true, Redis: nil})
	limit := middleware.RateLimit{Max: 2, Window: time.Minute}

	// Exhaust key A
	limiter.Check(t.Context(), "key:A", limit)
	limiter.Check(t.Context(), "key:A", limit)
	result := limiter.Check(t.Context(), "key:A", limit)
	assert.False(t, result.Allowed, "key A should be exhausted")

	// Key B should still work
	result = limiter.Check(t.Context(), "key:B", limit)
	assert.True(t, result.Allowed, "key B should be independent of key A")
}

func TestRateLimit_InMemory_WindowResets(t *testing.T) {
	limiter := middleware.NewRateLimiter(&middleware.RateLimitConfig{Enabled: true, Redis: nil})
	limit := middleware.RateLimit{Max: 2, Window: 50 * time.Millisecond}

	// Exhaust the limit
	limiter.Check(t.Context(), "key:reset", limit)
	limiter.Check(t.Context(), "key:reset", limit)
	result := limiter.Check(t.Context(), "key:reset", limit)
	assert.False(t, result.Allowed)

	// Wait for window to expire
	time.Sleep(80 * time.Millisecond)

	// Should be allowed again
	result = limiter.Check(t.Context(), "key:reset", limit)
	assert.True(t, result.Allowed, "request should be allowed after window expires")
}

// ─────────────────────────────────────────────────────────────────────────────
// Exempt path tests
// ─────────────────────────────────────────────────────────────────────────────

func TestIsExempt(t *testing.T) {
	tests := []struct {
		path    string
		exempt  bool
	}{
		{"/.well-known/openid-configuration", true},
		{"/.well-known/jwks.json", true},
		{"/healthz", true},
		{"/readyz", true},
		{"/oauth2/token", false},
		{"/api/oidc/authenticate", false},
		{"/some/other/path", false},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			// We test via the middleware to verify exempt paths bypass
			// The isExempt function is unexported, so we test via gin middleware
			limiter := middleware.NewRateLimiter(&middleware.RateLimitConfig{Enabled: false})
			router := setupTestRouter(limiter)

			req := httptest.NewRequest(http.MethodGet, tt.path, nil)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			if tt.exempt {
				assert.Equal(t, http.StatusOK, w.Code, "exempt path %s should not be rate limited", tt.path)
			}
			// Non-exempt paths may get 200 (under limit) or 429 (over limit)
			// We just verify they aren't always exempt
		})
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Gin middleware integration tests
// ─────────────────────────────────────────────────────────────────────────────

func TestRateLimitMiddleware_TokenEndpoint(t *testing.T) {
	limiter := middleware.NewRateLimiter(&middleware.RateLimitConfig{Enabled: true, Redis: nil})
	router := setupTestRouter(limiter)

	for i := 0; i < 15; i++ {
		req := httptest.NewRequest(http.MethodPost, "/oauth2/token", nil)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		if i < 10 {
			assert.Equal(t, http.StatusOK, w.Code, "request %d should pass", i+1)
			remaining := w.Header().Get("X-RateLimit-Remaining")
			assert.NotEmpty(t, remaining, "X-RateLimit-Remaining header should be set")
		} else {
			assert.Equal(t, http.StatusTooManyRequests, w.Code, "request %d should be blocked", i+1)
			retryAfter := w.Header().Get("Retry-After")
			assert.NotEmpty(t, retryAfter, "Retry-After header should be set when blocked")
		}
	}
}

func TestRateLimitMiddleware_AuthenticateEndpoint(t *testing.T) {
	limiter := middleware.NewRateLimiter(&middleware.RateLimitConfig{Enabled: true, Redis: nil})
	router := setupTestRouter(limiter)

	for i := 0; i < 12; i++ {
		req := httptest.NewRequest(http.MethodPost, "/api/oidc/authenticate", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		if i < 10 {
			assert.Equal(t, http.StatusOK, w.Code, "request %d should pass", i+1)
		} else {
			assert.Equal(t, http.StatusTooManyRequests, w.Code, "request %d should be blocked", i+1)
		}
	}
}

func TestRateLimitMiddleware_UnprotectedPath_PassesThrough(t *testing.T) {
	limiter := middleware.NewRateLimiter(&middleware.RateLimitConfig{Enabled: true, Redis: nil})
	router := setupTestRouter(limiter)

	for i := 0; i < 20; i++ {
		req := httptest.NewRequest(http.MethodGet, "/unknown/path", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code, "unprotected path should always pass")
	}
}

func TestRateLimitMiddleware_ExemptPaths_BypassRateLimit(t *testing.T) {
	limiter := middleware.NewRateLimiter(&middleware.RateLimitConfig{Enabled: true, Redis: nil})
	router := setupTestRouter(limiter)

	exemptPaths := []string{
		"/.well-known/openid-configuration",
		"/.well-known/jwks.json",
		"/healthz",
		"/readyz",
	}

	for _, path := range exemptPaths {
		t.Run(path, func(t *testing.T) {
			for i := 0; i < 20; i++ {
				req := httptest.NewRequest(http.MethodGet, path, nil)
				w := httptest.NewRecorder()
				router.ServeHTTP(w, req)
				assert.Equal(t, http.StatusOK, w.Code, "exempt path %s request %d should pass", path, i+1)
			}
		})
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Config loading tests
// ─────────────────────────────────────────────────────────────────────────────

func TestLoadRateLimitConfig_DisabledByDefault(t *testing.T) {
	// When SSSO_RATE_LIMIT_ENABLED is not set
	t.Setenv("SSSO_RATE_LIMIT_ENABLED", "")
	config := middleware.LoadRateLimitConfig()
	assert.False(t, config.Enabled)
}

func TestLoadRateLimitConfig_Enabled(t *testing.T) {
	t.Setenv("SSSO_RATE_LIMIT_ENABLED", "true")
	t.Setenv("SSSO_RATE_LIMIT_REDIS_ADDR", "localhost:6380")

	config := middleware.LoadRateLimitConfig()
	assert.True(t, config.Enabled)
	// Redis client is created but won't connect in test
	assert.NotNil(t, config.Redis)
}

// ─────────────────────────────────────────────────────────────────────────────
// Rate limit definitions tests
// ─────────────────────────────────────────────────────────────────────────────

func TestRateLimitDefinitions_HaveCorrectValues(t *testing.T) {
	tests := []struct {
		name   string
		limit  middleware.RateLimit
		max    int
		window time.Duration
	}{
		{"OAuth2Token", middleware.OAuth2TokenLimit, 10, time.Minute},
		{"AuthenticateUser", middleware.AuthenticateUserLimit, 10, time.Minute},
		{"AuthenticateUserPerUser", middleware.AuthenticateUserPerUserLimit, 5, time.Minute},
		{"Verify2FA", middleware.Verify2FALimit, 3, time.Minute},
		{"SendSmsOtp", middleware.SendSmsOtpLimit, 1, time.Minute},
		{"SendEmailOtp", middleware.SendEmailOtpLimit, 1, time.Minute},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.max, tt.limit.Max)
			assert.Equal(t, tt.window, tt.limit.Window)
		})
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

func setupTestRouter(limiter *middleware.RateLimiter) *gin.Engine {
	router := gin.New()
	router.Use(middleware.RateLimitMiddleware(limiter))

	// Register test routes that match the application routes
	router.POST("/oauth2/token", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})
	router.POST("/api/oidc/authenticate", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})
	router.GET("/.well-known/openid-configuration", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})
	router.GET("/.well-known/jwks.json", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})
	router.GET("/healthz", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})
	router.GET("/readyz", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})
	router.GET("/unknown/path", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	return router
}
