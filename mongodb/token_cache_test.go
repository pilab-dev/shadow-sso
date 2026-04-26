package mongodb_test

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/pilab-dev/shadow-sso/cache"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"

	"github.com/pilab-dev/shadow-sso/mongodb"
)

// makeTestTokenEntry creates a cache.TokenEntry with the given token value and TTL.
func makeTestTokenEntry(tokenValue string, ttl time.Duration) *cache.TokenEntry {
	now := time.Now().UTC().Truncate(time.Millisecond)
	return &cache.TokenEntry{
		TokenValue: tokenValue,
		TokenType:  "access_token",
		ClientID:   "test-client",
		UserID:     "test-user",
		Scope:      "openid profile",
		ExpiresAt:  now.Add(ttl),
		IsRevoked:  false,
		CreatedAt:  now,
		LastUsedAt: now,
		Roles:      []string{"user"},
	}
}

// setupTokenCacheTest creates a MongoTokenStore backed by a temporary MongoDB
// database. It returns the store, a cleanup function, and an error.
func setupTokenCacheTest(t *testing.T) (cache.TokenStore, func(), error) {
	mongoURI := os.Getenv("MONGO_TEST_URI")
	if mongoURI == "" {
		mongoURI = "mongodb://localhost:27017"
	}
	dbName := fmt.Sprintf("test_sso_token_cache_%d", time.Now().UnixNano())

	ctx, cancelSetup := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancelSetup()

	client, err := mongo.Connect(options.Client().ApplyURI(mongoURI).SetConnectTimeout(10 * time.Second))
	if err != nil {
		return nil, func() {}, fmt.Errorf("mongo.Connect failed for token cache test: %w", err)
	}
	if errPing := client.Ping(ctx, nil); errPing != nil {
		client.Disconnect(ctx)
		return nil, func() {}, fmt.Errorf("mongo.Ping failed for token cache test: %w", errPing)
	}
	db := client.Database(dbName)

	tokenCache := mongodb.NewTokenCache(db)

	cleanupFunc := func() {
		mainCtx := context.Background()
		if errDbDrop := db.Drop(mainCtx); errDbDrop != nil {
			t.Logf("Warning: failed to drop database %s during cleanup: %v", dbName, errDbDrop)
		}
		if errDisconnect := client.Disconnect(mainCtx); errDisconnect != nil {
			t.Logf("Warning: failed to disconnect test client during cleanup: %v", errDisconnect)
		}
	}
	return tokenCache, cleanupFunc, nil
}

func TestTokenCache_Integration(t *testing.T) {
	if os.Getenv("MONGO_TEST_URI") == "" {
		t.Skip("Skipping MongoDB integration test: MONGO_TEST_URI not set")
	}

	store, cleanup, err := setupTokenCacheTest(t)
	require.NoError(t, err, "Failed to setup TokenCache test")
	defer cleanup()

	ctx := context.Background()

	t.Run("SetAndGet", func(t *testing.T) {
		entry := makeTestTokenEntry("token-value-123", 1*time.Hour)
		err := store.Set(ctx, entry)
		require.NoError(t, err, "Set should succeed")

		fetched, err := store.Get(ctx, entry.TokenValue)
		require.NoError(t, err, "Get should succeed")
		require.NotNil(t, fetched, "Get should return a token entry")

		// Verify all fields match the original entry.
		assert.Equal(t, entry.TokenValue, fetched.TokenValue)
		assert.Equal(t, entry.TokenType, fetched.TokenType)
		assert.Equal(t, entry.ClientID, fetched.ClientID)
		assert.Equal(t, entry.UserID, fetched.UserID)
		assert.Equal(t, entry.Scope, fetched.Scope)
		assert.Equal(t, entry.IsRevoked, fetched.IsRevoked)
		assert.Equal(t, entry.Roles, fetched.Roles)
		assert.WithinDuration(t, entry.ExpiresAt, fetched.ExpiresAt, time.Second)
		assert.WithinDuration(t, entry.CreatedAt, fetched.CreatedAt, time.Second)

		// LastUsedAt is updated by Get() as a side effect, so it will differ
		// from the original. Just verify it is non-zero.
		assert.False(t, fetched.LastUsedAt.IsZero(), "LastUsedAt should be set")
	})

	t.Run("Get_NotFound", func(t *testing.T) {
		fetched, err := store.Get(ctx, "non-existent-token-value")
		require.NoError(t, err, "Get for missing token should return nil, nil")
		assert.Nil(t, fetched, "Get for missing token should return nil entry")
	})

	t.Run("Set_Upsert", func(t *testing.T) {
		tokenValue := "upsert-test-token"
		entry1 := makeTestTokenEntry(tokenValue, 1*time.Hour)
		entry1.Scope = "original-scope"

		err := store.Set(ctx, entry1)
		require.NoError(t, err, "First Set should succeed")

		// Store a second entry with the same token value but different fields.
		entry2 := makeTestTokenEntry(tokenValue, 2*time.Hour)
		entry2.Scope = "updated-scope"
		entry2.ClientID = "updated-client"

		err = store.Set(ctx, entry2)
		require.NoError(t, err, "Second Set should succeed (upsert)")

		fetched, err := store.Get(ctx, tokenValue)
		require.NoError(t, err)
		require.NotNil(t, fetched)
		assert.Equal(t, "updated-scope", fetched.Scope)
		assert.Equal(t, "updated-client", fetched.ClientID)
		assert.WithinDuration(t, entry2.ExpiresAt, fetched.ExpiresAt, time.Second)
	})

	t.Run("Delete", func(t *testing.T) {
		entry := makeTestTokenEntry("delete-me-token", 1*time.Hour)

		err := store.Set(ctx, entry)
		require.NoError(t, err)

		// Confirm it exists first.
		fetched, err := store.Get(ctx, entry.TokenValue)
		require.NoError(t, err)
		require.NotNil(t, fetched)

		// Delete and verify.
		err = store.Delete(ctx, entry.TokenValue)
		require.NoError(t, err, "Delete should succeed")

		fetched, err = store.Get(ctx, entry.TokenValue)
		require.NoError(t, err)
		assert.Nil(t, fetched, "Get after Delete should return nil")
	})

	t.Run("DeleteExpired", func(t *testing.T) {
		// Store one expired token (negative TTL) and one valid token.
		expiredToken := makeTestTokenEntry("expired-token", -1*time.Hour)
		validToken := makeTestTokenEntry("valid-token", 1*time.Hour)

		err := store.Set(ctx, expiredToken)
		require.NoError(t, err)
		err = store.Set(ctx, validToken)
		require.NoError(t, err)

		// Record count before cleanup.
		beforeCount := store.Count(ctx)

		err = store.DeleteExpired(ctx)
		require.NoError(t, err, "DeleteExpired should succeed")

		afterCount := store.Count(ctx)
		assert.Less(t, afterCount, beforeCount,
			"Count should decrease after deleting expired tokens")

		// The valid token must still be accessible.
		fetched, err := store.Get(ctx, "valid-token")
		require.NoError(t, err)
		require.NotNil(t, fetched, "Valid token should survive DeleteExpired")
		assert.Equal(t, "valid-token", fetched.TokenValue)

		// The expired token must be gone.
		fetched, err = store.Get(ctx, "expired-token")
		require.NoError(t, err)
		assert.Nil(t, fetched, "Expired token should be removed by DeleteExpired")
	})

	t.Run("Clear", func(t *testing.T) {
		err := store.Set(ctx, makeTestTokenEntry("clear-test-token-1", 1*time.Hour))
		require.NoError(t, err)
		err = store.Set(ctx, makeTestTokenEntry("clear-test-token-2", 1*time.Hour))
		require.NoError(t, err)

		err = store.Clear(ctx)
		require.NoError(t, err, "Clear should succeed")

		count := store.Count(ctx)
		assert.Equal(t, 0, count, "Count should be 0 after Clear")
	})

	t.Run("Count", func(t *testing.T) {
		// Clear first to get a known baseline.
		err := store.Clear(ctx)
		require.NoError(t, err)

		err = store.Set(ctx, makeTestTokenEntry("count-test-token-1", 1*time.Hour))
		require.NoError(t, err)
		err = store.Set(ctx, makeTestTokenEntry("count-test-token-2", 1*time.Hour))
		require.NoError(t, err)

		count := store.Count(ctx)
		assert.Equal(t, 2, count, "Count should return 2 after storing 2 tokens")
	})
}
