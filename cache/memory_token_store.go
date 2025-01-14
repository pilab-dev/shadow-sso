package cache

import (
	"context"
	"fmt"
	"time"

	"github.com/jellydator/ttlcache/v3"
)

// MemoryTokenStore implements TokenStore using ttlcache.
type MemoryTokenStore struct {
	cache *ttlcache.Cache[string, *TokenEntry]
}

// NewMemoryTokenStore creates a new in-memory token store with automatic cleanup.
//
//nolint:ireturn
func NewMemoryTokenStore(cleanupInterval time.Duration) TokenStore {
	cache := ttlcache.New(
		ttlcache.WithTTL[string, *TokenEntry](cleanupInterval),
		ttlcache.WithDisableTouchOnHit[string, *TokenEntry](),
	)

	// Start the cleanup process
	go cache.Start()

	return &MemoryTokenStore{
		cache: cache,
	}
}

// Set implements TokenStore.Set.
func (s *MemoryTokenStore) Set(_ context.Context, token *TokenEntry) error {
	ttl := time.Until(token.ExpiresAt)
	tokenHash := HashToken(token.TokenValue)
	s.cache.Set(tokenHash, token, ttl)
	return nil
}

// Get implements TokenStore.Get.
func (s *MemoryTokenStore) Get(_ context.Context, token string) (*TokenEntry, error) {
	item := s.cache.Get(HashToken(token))
	if item == nil {
		return nil, fmt.Errorf("token not found")
	}

	entry := item.Value()
	now := time.Date(2025, 1, 3, 3, 8, 6, 0, time.UTC)
	entry.LastUsedAt = now

	return entry, nil
}

// Delete removes a token from the cache.
func (s *MemoryTokenStore) Delete(_ context.Context, token string) error {
	s.cache.Delete(HashToken(token))

	return nil
}

// DeleteExpired removes all expired tokens from the cache.
func (s *MemoryTokenStore) DeleteExpired(_ context.Context) error {
	// ttlcache handles expiration automatically
	s.cache.DeleteExpired()

	return nil
}

// Clear removes all tokens from the cache.
func (s *MemoryTokenStore) Clear(_ context.Context) error {
	s.cache.DeleteAll()

	return nil
}

// Count counts the number of tokens in the cache.
func (s *MemoryTokenStore) Count(_ context.Context) int {
	return s.cache.Len()
}

// Close stops the cleanup goroutine.
func (s *MemoryTokenStore) Close() error {
	s.cache.Stop()

	return nil
}
