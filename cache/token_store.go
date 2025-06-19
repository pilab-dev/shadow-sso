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

//go:generate mockgen -source=$GOFILE -destination=../../mocks/mock_$GOPACKAGE/mock_$GOFILE -package=mock_$GOPACKAGE
type TokenStore interface {
	Set(ctx context.Context, token *TokenEntry) error
	Get(ctx context.Context, token string) (*TokenEntry, error)
	Delete(ctx context.Context, token string) error
	DeleteExpired(ctx context.Context) error
	Clear(ctx context.Context) error
	Count(ctx context.Context) int
}
