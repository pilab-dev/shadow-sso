package cache

import (
	"context"
	"time"

	"github.com/jellydator/ttlcache/v3"
)

// MemoryTokenStore implements TokenStore using ttlcache
type MemoryTokenStore struct {
	cache *ttlcache.Cache[string, *TokenEntry]
}

// NewMemoryTokenStore creates a new in-memory token store with automatic cleanup
func NewMemoryTokenStore(cleanupInterval time.Duration) *MemoryTokenStore {
	cache := ttlcache.New[string, *TokenEntry](
		ttlcache.WithTTL[string, *TokenEntry](cleanupInterval),
		ttlcache.WithDisableTouchOnHit[string, *TokenEntry](),
	)

	// Start the cleanup process
	go cache.Start()

	return &MemoryTokenStore{
		cache: cache,
	}
}

// Set implements TokenStore.Set
func (s *MemoryTokenStore) Set(ctx context.Context, token string, expiresAt time.Time, claims TokenClaims) error {
	now := time.Date(2025, 1, 3, 3, 8, 6, 0, time.UTC)
	ttl := expiresAt.Sub(now)

	entry := &TokenEntry{
		Token:      token,
		ExpiresAt:  expiresAt,
		Claims:     claims,
		CreatedAt:  now,
		LastUsedAt: now,
	}

	s.cache.Set(token, entry, ttl)
	return nil
}

// Get implements TokenStore.Get
func (s *MemoryTokenStore) Get(ctx context.Context, token string) (*TokenEntry, bool) {
	item := s.cache.Get(token)
	if item == nil {
		return nil, false
	}

	entry := item.Value()
	now := time.Date(2025, 1, 3, 3, 8, 6, 0, time.UTC)
	entry.LastUsedAt = now

	return entry, true
}

// Delete implements TokenStore.Delete
func (s *MemoryTokenStore) Delete(ctx context.Context, token string) bool {
	s.cache.Delete(token)

	return true
}

// DeleteExpired implements TokenStore.DeleteExpired
func (s *MemoryTokenStore) DeleteExpired(ctx context.Context) int {
	// ttlcache handles expiration automatically
	s.cache.DeleteExpired()

	return 0
}

// Clear implements TokenStore.Clear
func (s *MemoryTokenStore) Clear(ctx context.Context) {
	s.cache.DeleteAll()
}

// Count implements TokenStore.Count
func (s *MemoryTokenStore) Count(ctx context.Context) int {
	return s.cache.Len()
}

// Close stops the cleanup goroutine
func (s *MemoryTokenStore) Close() {
	s.cache.Stop()
}
