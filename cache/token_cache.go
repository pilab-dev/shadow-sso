package cache

import (
	"context"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
)

// TokenCacheEntry represents a cached token with its metadata
type TokenCacheEntry struct {
	Token     string
	ExpiresAt time.Time
	Claims    interface{}
}

// TokenCache provides thread-safe caching for tokens with TTL
type TokenCache struct {
	mu    sync.RWMutex
	cache map[string]*TokenCacheEntry
	// cleanupInterval is how often cleanup runs
	cleanupInterval time.Duration
	done            chan struct{}
}

// NewTokenCache creates a new token cache with the specified cleanup interval
func NewTokenCache(cleanupInterval time.Duration) *TokenCache {
	cache := &TokenCache{
		mu:              sync.RWMutex{},
		cache:           make(map[string]*TokenCacheEntry),
		cleanupInterval: cleanupInterval,
		done:            make(chan struct{}),
	}

	// Start cleanup goroutine
	go cache.cleanupLoop()

	return cache
}

// Set stores a token in the cache with its expiration time and claims
func (tc *TokenCache) Set(ctx context.Context, tokenString string, expiresAt time.Time, claims interface{}) {
	tc.mu.Lock()
	defer tc.mu.Unlock()

	tc.cache[tokenString] = &TokenCacheEntry{
		Token:     tokenString,
		ExpiresAt: expiresAt,
		Claims:    claims,
	}

	log.Ctx(ctx).Debug().
		Str("token", tokenString[:8]+"...").
		Time("expires_at", expiresAt).
		Msg("token cached")
}

// Get retrieves a token and its claims from the cache
func (tc *TokenCache) Get(ctx context.Context, tokenString string) (*TokenCacheEntry, bool) {
	tc.mu.RLock()
	defer tc.mu.RUnlock()

	entry, exists := tc.cache[tokenString]
	if !exists {
		return nil, false
	}

	// Check if token has expired
	if time.Now().After(entry.ExpiresAt) {
		// Token has expired, remove it from cache
		go tc.Delete(ctx, tokenString)
		return nil, false
	}

	log.Ctx(ctx).Debug().
		Str("token", tokenString[:8]+"...").
		Msg("token cache hit")

	return entry, true
}

// Delete removes a token from the cache
func (tc *TokenCache) Delete(ctx context.Context, tokenString string) {
	tc.mu.Lock()
	defer tc.mu.Unlock()

	delete(tc.cache, tokenString)
	log.Ctx(ctx).Debug().
		Str("token", tokenString[:8]+"...").
		Msg("token removed from cache")
}

// cleanup removes expired tokens from the cache
func (tc *TokenCache) cleanup() {
	tc.mu.Lock()
	defer tc.mu.Unlock()

	now := time.Now()
	for tokenString, entry := range tc.cache {
		if now.After(entry.ExpiresAt) {
			delete(tc.cache, tokenString)
		}
	}
}

// cleanupLoop runs the cleanup process periodically
func (tc *TokenCache) cleanupLoop() {
	ticker := time.NewTicker(tc.cleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			tc.cleanup()
		case <-tc.done:
			return
		}
	}
}

// Close stops the cleanup goroutine
func (tc *TokenCache) Close() {
	close(tc.done)
}
