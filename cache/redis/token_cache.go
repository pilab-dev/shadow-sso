package redis // Replace with your actual package name

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"
	"go.pilab.hu/sso/cache"
)

// TokenStore implements the TokenStore interface using Redis
type TokenStore struct {
	client *redis.Client
	prefix string // Optional prefix for keys
}

// NewTokenStore creates a new [TokenStore] instance
func NewTokenStore(client *redis.Client, prefix string) *TokenStore {
	return &TokenStore{
		client: client,
		prefix: prefix,
	}
}

// redisKey returns the Redis key for a given token
func (r *TokenStore) redisKey(token string) string {
	return fmt.Sprintf("%s:token:%s", r.prefix, token)
}

// Set stores a token with its claims and expiry time in Redis
func (r *TokenStore) Set(ctx context.Context, token string, expiresAt time.Time, claims cache.TokenClaims) error {
	key := r.redisKey(token)
	now := time.Now()

	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return fmt.Errorf("failed to marshal claims: %w", err)
	}

	entry := map[string]interface{}{
		"token":        token,
		"expires_at":   expiresAt.Unix(),
		"claims":       string(claimsJSON),
		"created_at":   now.Unix(),
		"last_used_at": now.Unix(),
	}

	_, err = r.client.HSet(ctx, key, entry).Result()
	if err != nil {
		return fmt.Errorf("failed to set token in Redis: %w", err)
	}

	// Set the expiry for the key
	expiryDuration := time.Until(expiresAt)
	_, err = r.client.Expire(ctx, key, expiryDuration).Result()
	if err != nil {
		return fmt.Errorf("failed to set expiry for token in Redis: %w", err)
	}

	return nil
}

// Get retrieves a token entry from Redis
func (r *TokenStore) Get(ctx context.Context, token string) (*cache.TokenEntry, bool) {
	key := r.redisKey(token)

	res, err := r.client.HGetAll(ctx, key).Result()
	if err != nil {
		return nil, false // Consider logging the error if needed
	}

	if len(res) == 0 {
		return nil, false // Token not found
	}

	expiresAtUnix, err := strconv.ParseInt(res["expires_at"], 10, 64)
	if err != nil {
		return nil, false // Handle parsing error
	}

	createdAtUnix, err := strconv.ParseInt(res["created_at"], 10, 64)
	if err != nil {
		return nil, false // Handle parsing error
	}

	lastUsedAtUnix, err := strconv.ParseInt(res["last_used_at"], 10, 64)
	if err != nil {
		return nil, false // Handle parsing error
	}

	var claims cache.TokenClaims
	if claimsJSON, ok := res["claims"]; ok {
		if err := json.Unmarshal([]byte(claimsJSON), &claims); err != nil {
			// Consider logging the error, but still return the basic TokenEntry if needed
			fmt.Printf("Error unmarshaling claims: %v\n", err)
		}
	}

	entry := &cache.TokenEntry{
		Token:      res["token"],
		ExpiresAt:  time.Unix(expiresAtUnix, 0),
		Claims:     claims,
		CreatedAt:  time.Unix(createdAtUnix, 0),
		LastUsedAt: time.Unix(lastUsedAtUnix, 0),
	}

	// Update LastUsedAt
	_, err = r.client.HSet(ctx, key, "last_used_at", time.Now().Unix()).Result()
	if err != nil {
		// Log the error, but don't fail the Get operation
		fmt.Printf("Error updating last_used_at: %v\n", err)
	}

	return entry, true
}

// Delete removes a token from Redis
func (r *TokenStore) Delete(ctx context.Context, token string) bool {
	key := r.redisKey(token)
	res, err := r.client.Del(ctx, key).Result()
	if err != nil {
		return false // Consider logging the error
	}
	return res > 0
}

// DeleteExpired removes all expired tokens from Redis
func (r *TokenStore) DeleteExpired(ctx context.Context) int {
	var deletedCount int
	var cursor uint64
	pattern := r.redisKey("*") // Scan for all token keys

	for {
		var keys []string
		var err error
		keys, cursor, err = r.client.Scan(ctx, cursor, pattern, 100).Result()
		if err != nil {
			fmt.Printf("Error scanning for expired tokens: %v\n", err)
			break
		}

		if len(keys) > 0 {
			for _, key := range keys {
				res, err := r.client.HGet(ctx, key, "expires_at").Result()
				if err == redis.Nil {
					continue // Key might have been deleted in the meantime
				} else if err != nil {
					fmt.Printf("Error getting expiry for key %s: %v\n", key, err)
					continue
				}

				expiresAtUnix, err := strconv.ParseInt(res, 10, 64)
				if err != nil {
					fmt.Printf("Error parsing expiry for key %s: %v\n", key, err)
					continue
				}

				if time.Unix(expiresAtUnix, 0).Before(time.Now()) {
					deleted, err := r.client.Del(ctx, key).Result()
					if err != nil {
						fmt.Printf("Error deleting expired key %s: %v\n", key, err)
					} else if deleted > 0 {
						deletedCount++
					}
				}
			}
		}

		if cursor == 0 {
			break // No more keys to scan
		}
	}

	return deletedCount
}

// Clear removes all tokens from Redis
func (r *TokenStore) Clear(ctx context.Context) {
	pattern := r.redisKey("*")
	var cursor uint64

	for {
		var keys []string
		var err error
		keys, cursor, err = r.client.Scan(ctx, cursor, pattern, 100).Result()
		if err != nil {
			fmt.Printf("Error scanning for keys to clear: %v\n", err)
			return
		}

		if len(keys) > 0 {
			_, err = r.client.Del(ctx, keys...).Result()
			if err != nil {
				fmt.Printf("Error deleting keys: %v\n", err)
			}
		}

		if cursor == 0 {
			break
		}
	}
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
