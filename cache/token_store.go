package cache

import (
	"context"
	"time"
)

// TokenClaims represents the claims stored in the cache
type TokenClaims interface{}

// TokenEntry represents a cached token entry
type TokenEntry struct {
	Token      string
	ExpiresAt  time.Time
	Claims     TokenClaims
	CreatedAt  time.Time
	LastUsedAt time.Time
}

// TokenStore defines the interface for token caching implementations
type TokenStore interface {
	// Set stores a token with its claims and expiry time
	Set(ctx context.Context, token string, expiresAt time.Time, claims TokenClaims) error

	// Get retrieves a token entry from the cache
	Get(ctx context.Context, token string) (*TokenEntry, bool)

	// Delete removes a token from the cache
	Delete(ctx context.Context, token string) bool

	// DeleteExpired removes all expired tokens from the cache
	DeleteExpired(ctx context.Context) int

	// Clear removes all tokens from the cache
	Clear(ctx context.Context)

	// Count returns the number of tokens in the cache
	Count(ctx context.Context) int
}
