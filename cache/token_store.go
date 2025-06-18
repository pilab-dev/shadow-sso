package cache

import (
	"context"
	"time"
)

// TokenEntry represents a cached token entry
type TokenEntry struct {
	ID         string    `redis:"id"`         // Unique token identifier
	TokenType  string    `redis:"tokenType"`  // "access_token" or "refresh_token"
	TokenValue string    `redis:"tokenValue"` // The actual token string
	ClientID   string    `redis:"clientId"`   // Client that requested the token
	UserID     string    `redis:"userId"`     // User who authorized the token
	Scope      string    `redis:"scope"`      // Authorized scopes
	ExpiresAt  time.Time `redis:"expiresAt"`  // Expiration timestamp
	IsRevoked  bool      `redis:"isRevoked"`  // Whether token is revoked
	CreatedAt  time.Time `redis:"createdAt"`  // Creation timestamp
	LastUsedAt time.Time `redis:"lastUsedAt"` // Last usage timestamp
	Roles      []string  `redis:"roles,omitempty"` // New field
}

// TokenStore defines the interface for token caching implementations
type TokenStore interface {
	// Set stores a token with its claims and expiry time
	Set(ctx context.Context, token *TokenEntry) error

	// Get retrieves a token entry from the cache
	Get(ctx context.Context, token string) (*TokenEntry, error)

	// Delete removes a token from the cache
	Delete(ctx context.Context, token string) error

	// DeleteExpired removes all expired tokens from the cache
	DeleteExpired(ctx context.Context) error

	// Clear removes all tokens from the cache
	Clear(ctx context.Context) error

	// Count returns the number of tokens in the cache
	Count(ctx context.Context) int
}
