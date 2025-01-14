//go:build redis

// Package redis implements the TokenStore interface using Redis.
// To use this package, you need to enable the "redis" build tag.
package redis

import (
	"context"
	"fmt"
	"strconv"
	"time"

	ssso "github.com/pilab-dev/shadow-sso"
	"github.com/redis/go-redis/v9"
)

// TokenStore implements the TokenStore interface using Redis
type TokenStore struct {
	client *redis.Client
	prefix string // Optional prefix for keys
}

// NewTokenStore creates a new [TokenStore] instance
func NewTokenStore(client *redis.Client, prefix string) ssso.TokenStore {
	return &TokenStore{
		client: client,
		prefix: prefix,
	}
}

// redisKey returns the Redis key for a given token
func (r *TokenStore) redisKey(tokenHash string) string {
	return fmt.Sprintf("%s:token:%s", r.prefix, tokenHash)
}

type TokenEntry struct {
	ID         string    `redis:"id"`           // Unique token identifier
	TokenType  string    `redis:"token_type"`   // "access_token" or "refresh_token"
	TokenValue string    `redis:"token_value"`  // The actual token string
	ClientID   string    `redis:"client_id"`    // Client that requested the token
	UserID     string    `redis:"user_id"`      // User who authorized the token
	Scope      string    `redis:"scope"`        // Authorized scopes
	ExpiresAt  time.Time `redis:"expires_at"`   // Expiration timestamp
	IsRevoked  bool      `redis:"is_revoked"`   // Whether token is revoked
	CreatedAt  time.Time `redis:"created_at"`   // Creation timestamp
	LastUsedAt time.Time `redis:"last_used_at"` // Last usage timestamp
}

func NewTokenEntry(token *ssso.Token) TokenEntry {
	return TokenEntry{
		ID:         token.ID,
		TokenType:  token.TokenType,
		TokenValue: token.TokenValue,
		ClientID:   token.ClientID,
		UserID:     token.UserID,
		Scope:      token.Scope,
		ExpiresAt:  token.ExpiresAt,
		IsRevoked:  token.IsRevoked,
		CreatedAt:  token.CreatedAt,
		LastUsedAt: token.LastUsedAt,
	}
}

func (t *TokenEntry) Token() *ssso.Token {
	return &ssso.Token{
		ID:         t.ID,
		TokenType:  t.TokenType,
		TokenValue: t.TokenValue,
		ClientID:   t.ClientID,
		UserID:     t.UserID,
		Scope:      t.Scope,
		ExpiresAt:  t.ExpiresAt,
		IsRevoked:  t.IsRevoked,
		CreatedAt:  t.CreatedAt,
		LastUsedAt: t.LastUsedAt,
	}
}

// Set stores a token with its claims and expiry time in Redis
func (r *TokenStore) Set(ctx context.Context, token *ssso.Token) error {
	tokenHash := ssso.HashToken(token.TokenValue)

	key := r.redisKey(tokenHash)

	entry := NewTokenEntry(token)

	_, err := r.client.HSet(ctx, key, entry).Result()
	if err != nil {
		return fmt.Errorf("failed to set token in Redis: %w", err)
	}

	// Set the expiry for the key
	expiryDuration := time.Until(token.ExpiresAt)
	_, err = r.client.Expire(ctx, key, expiryDuration).Result()
	if err != nil {
		return fmt.Errorf("failed to set expiry for token in Redis: %w", err)
	}

	return nil
}

// Get retrieves a token entry from Redis
func (r *TokenStore) Get(ctx context.Context, tokenValue string) (*ssso.Token, bool) {
	key := r.redisKey(ssso.HashToken(tokenValue))

	var entry TokenEntry

	err := r.client.HGetAll(ctx, key).Scan(&entry)
	if err != nil {
		return nil, false // Consider logging the error if needed
	}

	// Update LastUsedAt
	_, err = r.client.HSet(ctx, key, "last_used_at", time.Now().Unix()).Result()
	if err != nil {
		// Log the error, but don't fail the Get operation
		fmt.Printf("Error updating last_used_at: %v\n", err)
	}

	return entry.Token(), true
}

// Delete removes a token from Redis
func (r *TokenStore) Delete(ctx context.Context, token string) error {
	key := r.redisKey(ssso.HashToken(token))

	res, err := r.client.Del(ctx, key).Result()
	if err != nil {
		return fmt.Errorf("failed to delete token from Redis: %w", err)
	}

	if res == 0 {
		return fmt.Errorf("token not found")
	}

	return nil
}

// DeleteExpired removes all expired tokens from Redis
func (r *TokenStore) DeleteExpired(ctx context.Context) error {
	// var deletedCount int
	var cursor uint64
	pattern := r.redisKey("*") // Scan for all token keys

	for {
		var keys []string
		var err error
		keys, cursor, err = r.client.Scan(ctx, cursor, pattern, 100).Result()
		if err != nil {
			return fmt.Errorf("error scanning for expired tokens: %w", err)
		}

		if len(keys) > 0 {
			for _, key := range keys {
				res, err := r.client.HGet(ctx, key, "expires_at").Result()
				if err == redis.Nil {
					continue // Key might have been deleted in the meantime
				} else if err != nil {
					return fmt.Errorf("error getting expiry for key %s: %w", key, err)
				}

				expiresAtUnix, err := strconv.ParseInt(res, 10, 64)
				if err != nil {
					return fmt.Errorf("error parsing expiry for key %s: %w", key, err)
				}

				if time.Unix(expiresAtUnix, 0).Before(time.Now()) {
					deleted, err := r.client.Del(ctx, key).Result()
					if err != nil {
						return fmt.Errorf("error deleting expired key %s: %w", key, err)
					} else if deleted > 0 {
						// deletedCount++
					}
				}
			}
		}

		if cursor == 0 {
			break // No more keys to scan
		}
	}

	return nil
}

// Clear removes all tokens from Redis
func (r *TokenStore) Clear(ctx context.Context) error {
	pattern := r.redisKey("*")
	var cursor uint64

	for {
		var keys []string
		var err error
		keys, cursor, err = r.client.Scan(ctx, cursor, pattern, 100).Result()
		if err != nil {
			return fmt.Errorf("Error scanning for keys to clear: %w", err)
		}

		if len(keys) > 0 {
			_, err = r.client.Del(ctx, keys...).Result()
			if err != nil {
				return fmt.Errorf("Error deleting keys: %w", err)
			}
		}

		if cursor == 0 {
			break
		}
	}

	return nil
}

// Count returns the number of tokens in Redis
func (r *TokenStore) Count(ctx context.Context) int {
	pattern := r.redisKey("*")
	var count int64
	var cursor uint64

	for {
		var keys []string
		var err error
		keys, cursor, err = r.client.Scan(ctx, cursor, pattern, 100).Result()
		if err != nil {
			fmt.Printf("Error scanning for keys: %v\n", err)
			break
		}
		count += int64(len(keys))
		if cursor == 0 {
			break
		}
	}
	return int(count)
}

// Close closes the Redis client
func (r *TokenStore) Close() error {
	return r.client.Close()
}
