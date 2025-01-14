package ssso

import (
	"context"
	"io"
)

// TokenStore represents the interface for token caching operations.
// This interface provides methods to manage a temporary token cache for improved performance.
type TokenStore interface {
	// Close closes the token store.
	io.Closer

	// Token Cache Operations

	// Set stores a token in the cache.
	// Returns an error if the operation fails.
	Set(ctx context.Context, token *Token) error

	// Get retrieves a token from the cache by its value.
	// Returns the token and true if found, or nil and false if not found.
	Get(ctx context.Context, tokenValue string) (*Token, bool)

	// Delete removes a token from the cache.
	// Returns an error if the operation fails.
	Delete(ctx context.Context, tokenValue string) error

	// Clear removes all tokens from the cache.
	// Returns an error if the operation fails.
	Clear(ctx context.Context) error

	// Maintenance Operations

	// DeleteExpired removes all expired tokens from the cache.
	// Returns an error if the operation fails.
	DeleteExpired(ctx context.Context) error

	// Count returns the number of tokens currently in the cache.
	Count(ctx context.Context) int
}
