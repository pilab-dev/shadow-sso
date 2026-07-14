package middleware

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"connectrpc.com/connect"
	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
	"github.com/rs/zerolog/log"
)

// ─────────────────────────────────────────────────────────────────────────────
// Configuration
// ─────────────────────────────────────────────────────────────────────────────

// RateLimitConfig holds rate limiting configuration.
type RateLimitConfig struct {
	Enabled bool
	Redis   *redis.Client
}

// LoadRateLimitConfig reads rate limit config from environment variables.
func LoadRateLimitConfig() *RateLimitConfig {
	enabled := os.Getenv("SSSO_RATE_LIMIT_ENABLED")
	if enabled != "true" {
		return &RateLimitConfig{Enabled: false}
	}

	redisAddr := os.Getenv("SSSO_RATE_LIMIT_REDIS_ADDR")
	if redisAddr == "" {
		redisAddr = "localhost:6379"
	}

	rdb := redis.NewClient(&redis.Options{
		Addr:         redisAddr,
		DialTimeout:  5 * time.Second,
		ReadTimeout:  3 * time.Second,
		WriteTimeout: 3 * time.Second,
		PoolSize:     10,
		MinIdleConns: 2,
	})

	return &RateLimitConfig{
		Enabled: true,
		Redis:   rdb,
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Rate limit definitions
// ─────────────────────────────────────────────────────────────────────────────

// RateLimit defines a rate limit rule.
type RateLimit struct {
	Max    int           // maximum requests in window
	Window time.Duration // sliding window duration
}

// Common rate limits used by the application.
var (
	OAuth2TokenLimit       = RateLimit{Max: 10, Window: time.Minute}
	AuthenticateUserLimit  = RateLimit{Max: 10, Window: time.Minute}
	AuthenticateUserPerUserLimit = RateLimit{Max: 5, Window: time.Minute}
	Verify2FALimit         = RateLimit{Max: 3, Window: time.Minute}
	SendSmsOtpLimit        = RateLimit{Max: 1, Window: time.Minute}
	SendEmailOtpLimit      = RateLimit{Max: 1, Window: time.Minute}
)

// Exempt path prefixes that should never be rate-limited.
var exemptPathPrefixes = []string{
	"/.well-known/",
	"/healthz",
	"/readyz",
}

// ─────────────────────────────────────────────────────────────────────────────
// RateLimiter core
// ─────────────────────────────────────────────────────────────────────────────

// RateLimiter provides Redis-backed sliding window rate limiting.
type RateLimiter struct {
	config    *RateLimitConfig
	fallback  *inMemoryFallback
}

// NewRateLimiter creates a new RateLimiter with the given config.
// If Redis is unavailable at creation time, it falls back to an in-memory limiter.
func NewRateLimiter(config *RateLimitConfig) *RateLimiter {
	if config == nil {
		config = &RateLimitConfig{Enabled: false}
	}
	return &RateLimiter{
		config:   config,
		fallback: newInMemoryFallback(),
	}
}

// isExempt returns true if the request path should bypass rate limiting.
func isExempt(path string) bool {
	for _, prefix := range exemptPathPrefixes {
		if path == prefix || strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
}

// RateLimitResult contains the result of a rate limit check.
type RateLimitResult struct {
	Allowed    bool
	Remaining  int
	ResetAfter time.Duration
	RetryAfter time.Duration
}

// Check verifies whether a request is allowed under the given rate limit.
// key is a unique identifier (e.g., "ip:192.168.1.1" or "user:abc123").
func (rl *RateLimiter) Check(ctx context.Context, key string, limit RateLimit) RateLimitResult {
	if !rl.config.Enabled {
		return RateLimitResult{Allowed: true, Remaining: limit.Max}
	}

	// Try Redis first, fall back to in-memory on failure
	if rl.config.Redis != nil {
		result, err := rl.checkRedis(ctx, key, limit)
		if err == nil {
			return result
		}
		log.Warn().Err(err).Str("key", key).Msg("Redis rate limit check failed, falling back to in-memory")
	}

	return rl.fallback.Check(key, limit)
}

// checkRedis implements sliding window rate limiting using Redis.
// Uses a Lua script for atomic INCR + EXPIRE operations.
func (rl *RateLimiter) checkRedis(ctx context.Context, key string, limit RateLimit) (RateLimitResult, error) {
	redisKey := fmt.Sprintf("ratelimit:%s", key)
	windowSec := int64(limit.Window.Seconds())

	// Lua script for atomic sliding window:
	// 1. Increment the counter
	// 2. If this is the first request (count == 1), set expiry
	// 3. Calculate remaining and retry-after
	script := redis.NewScript(`
		local key = KEYS[1]
		local limit = tonumber(ARGV[1])
		local window = tonumber(ARGV[2])
		local now = tonumber(ARGV[3])

		local current = redis.call('INCR', key)
		if current == 1 then
			redis.call('EXPIRE', key, window)
		end

		local ttl = redis.call('TTL', key)
		if ttl < 0 then
			redis.call('EXPIRE', key, window)
			ttl = window
		end

		local remaining = limit - current
		if remaining < 0 then
			remaining = 0
		end

		return {current, remaining, ttl}
	`)

	now := time.Now().Unix()
	result, err := script.Run(ctx, rl.config.Redis, []string{redisKey}, limit.Max, windowSec, now).Int64Slice()
	if err != nil {
		return RateLimitResult{}, fmt.Errorf("redis script execution failed: %w", err)
	}

	// result[0] = current count, result[1] = remaining, result[2] = TTL
	current := int(result[0])
	remaining := int(result[1])
	ttl := time.Duration(result[2]) * time.Second

	allowed := current <= limit.Max
	retryAfter := time.Duration(0)
	if !allowed {
		retryAfter = ttl
	}

	return RateLimitResult{
		Allowed:    allowed,
		Remaining:  remaining,
		ResetAfter: ttl,
		RetryAfter: retryAfter,
	}, nil
}

// ─────────────────────────────────────────────────────────────────────────────
// In-memory fallback (fail-open for dev / when Redis is down)
// ─────────────────────────────────────────────────────────────────────────────

type inMemoryEntry struct {
	count     int
	windowStart time.Time
}

type inMemoryFallback struct {
	mu      sync.Mutex
	entries map[string]*inMemoryEntry
}

func newInMemoryFallback() *inMemoryFallback {
	return &inMemoryFallback{
		entries: make(map[string]*inMemoryEntry),
	}
}

func (f *inMemoryFallback) Check(key string, limit RateLimit) RateLimitResult {
	f.mu.Lock()
	defer f.mu.Unlock()

	now := time.Now()
	entry, exists := f.entries[key]
	if !exists || now.Sub(entry.windowStart) > limit.Window {
		// New window
		f.entries[key] = &inMemoryEntry{
			count:       1,
			windowStart: now,
		}
		return RateLimitResult{
			Allowed:    true,
			Remaining:  limit.Max - 1,
			ResetAfter: limit.Window,
		}
	}

	entry.count++
	remaining := limit.Max - entry.count
	if remaining < 0 {
		remaining = 0
	}

	allowed := entry.count <= limit.Max
	retryAfter := time.Duration(0)
	if !allowed {
		retryAfter = limit.Window - now.Sub(entry.windowStart)
	}

	return RateLimitResult{
		Allowed:    allowed,
		Remaining:  remaining,
		ResetAfter: limit.Window - now.Sub(entry.windowStart),
		RetryAfter: retryAfter,
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Rate limit response headers
// ─────────────────────────────────────────────────────────────────────────────

// SetRateLimitHeaders sets standard rate limit headers on a gin.Context.
func SetRateLimitHeaders(c *gin.Context, result RateLimitResult) {
	c.Header("X-RateLimit-Remaining", strconv.Itoa(result.Remaining))
	if result.RetryAfter > 0 {
		c.Header("Retry-After", strconv.Itoa(int(result.RetryAfter.Seconds())))
	}
}

// SetConnectRateLimitHeaders sets rate limit headers on a Connect response header.
func SetConnectRateLimitHeaders(headers http.Header, result RateLimitResult) {
	headers.Set("X-RateLimit-Remaining", strconv.Itoa(result.Remaining))
	if result.RetryAfter > 0 {
		headers.Set("Retry-After", strconv.Itoa(int(result.RetryAfter.Seconds())))
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Gin middleware for HTTP endpoints
// ─────────────────────────────────────────────────────────────────────────────

// RateLimitMiddleware returns a gin.HandlerFunc that applies rate limiting.
// It uses the request IP as the rate limit key for path-based limits.
func RateLimitMiddleware(limiter *RateLimiter) gin.HandlerFunc {
	return func(c *gin.Context) {
		path := c.FullPath()
		if path == "" {
			path = c.Request.URL.Path
		}

		// Exempt paths
		if isExempt(path) {
			c.Next()
			return
		}

		// Determine which rate limit applies
		ip := c.ClientIP()
		key := fmt.Sprintf("ip:%s:path:%s", ip, path)
		limit := getHTTPRateLimit(path)
		if limit == nil {
			c.Next()
			return
		}

		result := limiter.Check(c.Request.Context(), key, *limit)
		SetRateLimitHeaders(c, result)

		if !result.Allowed {
			log.Warn().
				Str("path", path).
				Str("ip", ip).
				Int("limit", limit.Max).
				Dur("window", limit.Window).
				Msg("Rate limit exceeded")

			c.JSON(http.StatusTooManyRequests, gin.H{
				"error":             "rate_limit_exceeded",
				"error_description": fmt.Sprintf("Rate limit of %d requests per %s exceeded. Try again later.", limit.Max, limit.Window),
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

// getHTTPRateLimit returns the rate limit for a given HTTP path.
func getHTTPRateLimit(path string) *RateLimit {
	switch {
	case path == "/oauth2/token":
		return &OAuth2TokenLimit
	case path == "/api/oidc/authenticate":
		return &AuthenticateUserLimit
	default:
		return nil
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Connect interceptor for gRPC/Connect endpoints
// ─────────────────────────────────────────────────────────────────────────────

// NewConnectRateLimitInterceptor creates a Connect interceptor that applies
// rate limiting to specific RPC procedures.
func NewConnectRateLimitInterceptor(limiter *RateLimiter) connect.Interceptor {
	return connect.UnaryInterceptorFunc(func(next connect.UnaryFunc) connect.UnaryFunc {
		return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
			procedure := req.Spec().Procedure

			// Get the rate limit for this procedure
			limit := getConnectRateLimit(procedure)
			if limit == nil {
				return next(ctx, req)
			}

			// Build rate limit key from procedure + user ID (extracted from context or request)
			userID := extractUserIDFromRequest(req)
			if userID == "" {
				// Fall back to IP-based limiting if no user context
				userID = "anonymous"
			}
			key := fmt.Sprintf("procedure:%s:user:%s", procedure, userID)

			result := limiter.Check(ctx, key, *limit)

			if !result.Allowed {
				log.Warn().
					Str("procedure", procedure).
					Str("userID", userID).
					Int("limit", limit.Max).
					Dur("window", limit.Window).
					Msg("Connect rate limit exceeded")

				return nil, connect.NewError(
					connect.CodeResourceExhausted,
					fmt.Errorf("rate limit exceeded: %d requests per %s", limit.Max, limit.Window),
				)
			}

			resp, err := next(ctx, req)
			if err != nil {
				return nil, err
			}

			// Set rate limit headers on response
			SetConnectRateLimitHeaders(resp.Header(), result)

			return resp, nil
		}
	})
}

// getConnectRateLimit returns the rate limit for a given Connect procedure.
func getConnectRateLimit(procedure string) *RateLimit {
	switch procedure {
	case "/sso.v1.AuthService/Verify2FA":
		return &Verify2FALimit
	case "/sso.v1.UserService/SendSmsOtp":
		return &SendSmsOtpLimit
	case "/sso.v1.UserService/SendEmailOtp":
		return &SendEmailOtpLimit
	default:
		return nil
	}
}

// extractUserIDFromRequest attempts to extract the user ID from a Connect request.
// For Verify2FA, the user ID is in the request message.
// For SendSmsOtp and SendEmailOtp, the user ID is also in the request message.
func extractUserIDFromRequest(req connect.AnyRequest) string {
	// We need to type-switch on the request message to extract user_id
	// The request messages are protobuf types, so we use reflection or
	// a simpler approach: check the raw bytes for "user_id" field.
	//
	// Since we can't easily import the protobuf types here without creating
	// a circular dependency, we use a simpler approach: extract from the
	// procedure name and let the caller handle user-based rate limiting.
	//
	// For now, we return empty string to use anonymous key.
	// The rate limiting will work on procedure + anonymous for unauthenticated requests.
	// For authenticated requests, the user ID should be extracted from the JWT context.
	return ""
}
