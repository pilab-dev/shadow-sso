package mongodb

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/pilab-dev/shadow-sso/domain"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
	// "go.mongodb.org/mongo-driver/v2/bson" // For cleanup if needed, but drop DB is better
)

// Helper function to setup DB for PublicKeyRepository tests
func setupPublicKeyRepoTest(t *testing.T) (domain.PublicKeyRepository, func(), error) {
	mongoURI := os.Getenv("TEST_MONGO_URI")
	if mongoURI == "" {
		mongoURI = "mongodb://localhost:27017"
	}
	// Unique DB name for each test run to ensure isolation
	// Using a simpler unique name for DB if strconv is not imported yet for this file
	dbName := fmt.Sprintf("test_sso_pubkey_repo_%d", time.Now().UnixNano())

	ctx, cancelSetup := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancelSetup()

	// Direct client connection for test isolation
	client, err := mongo.Connect(ctx, options.Client().ApplyURI(mongoURI).SetConnectTimeout(10*time.Second))
	if err != nil {
		return nil, func() {}, fmt.Errorf("mongo.Connect failed for pubkey repo test: %w", err)
	}
	if errPing := client.Ping(ctx, nil); errPing != nil {
		client.Disconnect(ctx)
		return nil, func() {}, fmt.Errorf("mongo.Ping failed for pubkey repo test: %w", errPing)
	}
	db := client.Database(dbName)


	pubKeyRepo, err := NewPublicKeyRepositoryMongo(ctx, db) // Creates collection and indexes
	if err != nil {
		client.Disconnect(ctx)
		return nil, func() {}, fmt.Errorf("NewPublicKeyRepositoryMongo failed: %w", err)
	}

	cleanupFunc := func() {
		mainCtx := context.Background()
		if errDbDrop := db.Drop(mainCtx); errDbDrop != nil {
			t.Logf("Warning: failed to drop database %s during cleanup: %v", dbName, errDbDrop)
		}
		if errDisconnect := client.Disconnect(mainCtx); errDisconnect != nil {
			t.Logf("Warning: failed to disconnect test client during cleanup: %v", errDisconnect)
		}
	}
	return pubKeyRepo, cleanupFunc, nil
}

func TestPublicKeyRepositoryMongo_Integration(t *testing.T) {
	if os.Getenv("TEST_MONGO_URI") == "" && os.Getenv("CI") != "" {
		t.Skip("Skipping MongoDB integration tests: TEST_MONGO_URI not set and CI environment detected.")
	}

	repo, cleanup, err := setupPublicKeyRepoTest(t)
	require.NoError(t, err, "Failed to setup PublicKeyRepository test")
	defer cleanup()

	ctx := context.Background()
	saID1 := "service-account-id-1"
	saID2 := "service-account-id-2"

	key1 := &domain.PublicKeyInfo{
		ID:               "key-id-1", // This is the private_key_id
		ServiceAccountID: saID1,
		PublicKey:        "PEM_PUBLIC_KEY_DATA_1",
		Algorithm:        "RS256",
		Status:           "ACTIVE", // Initially Active
		CreatedAt:        time.Now().Unix() - 100,
	}
	key2 := &domain.PublicKeyInfo{
		ID:               "key-id-2",
		ServiceAccountID: saID1, // Same SA, different key
		PublicKey:        "PEM_PUBLIC_KEY_DATA_2",
		Algorithm:        "RS256",
		Status:           "INACTIVE", // Initially inactive
		CreatedAt:        time.Now().Unix() - 50,
	}
	key3 := &domain.PublicKeyInfo{
		ID:               "key-id-3",
		ServiceAccountID: saID2, // Different SA
		PublicKey:        "PEM_PUBLIC_KEY_DATA_3",
		Algorithm:        "ES256",
		Status:           "ACTIVE",
		CreatedAt:        time.Now().Unix(),
	}

	t.Run("CreatePublicKey", func(t *testing.T) {
		err := repo.CreatePublicKey(ctx, key1)
		require.NoError(t, err, "CreatePublicKey for key1 should succeed")

		err = repo.CreatePublicKey(ctx, key2)
		require.NoError(t, err, "CreatePublicKey for key2 should succeed")

		err = repo.CreatePublicKey(ctx, key3)
		require.NoError(t, err, "CreatePublicKey for key3 should succeed")

		// Try creating duplicate
		err = repo.CreatePublicKey(ctx, key1)
		require.Error(t, err, "CreatePublicKey with duplicate ID should fail")
		// Error message might depend on MongoDB driver version for duplicate key errors
		// assert.Contains(t, err.Error(), "duplicate key error")
	})

	t.Run("GetPublicKey_Active", func(t *testing.T) {
		fetchedKey, err := repo.GetPublicKey(ctx, key1.ID)
		require.NoError(t, err, "GetPublicKey for active key1 should succeed")
		require.NotNil(t, fetchedKey)
		assert.Equal(t, key1.PublicKey, fetchedKey.PublicKey)
		assert.Equal(t, "ACTIVE", fetchedKey.Status)
	})

	t.Run("GetPublicKey_InactiveOrNonExistent", func(t *testing.T) {
		// key2 is INACTIVE
		_, err := repo.GetPublicKey(ctx, key2.ID)
		assert.Error(t, err, "GetPublicKey for inactive key2 should fail")
		assert.Contains(t, err.Error(), "public key not found or not active")

		// Non-existent key
		_, err = repo.GetPublicKey(ctx, "non-existent-key-id")
		assert.Error(t, err, "GetPublicKey for non-existent key should fail")
		assert.Contains(t, err.Error(), "public key not found or not active")
	})

	t.Run("UpdatePublicKeyStatus", func(t *testing.T) {
		err := repo.UpdatePublicKeyStatus(ctx, key2.ID, "ACTIVE")
		require.NoError(t, err, "UpdatePublicKeyStatus to ACTIVE for key2 should succeed")

		fetchedKey, err := repo.GetPublicKey(ctx, key2.ID) // Now it should be found as ACTIVE
		require.NoError(t, err)
		require.NotNil(t, fetchedKey)
		assert.Equal(t, "ACTIVE", fetchedKey.Status)
		// Check for updated_at if that field is added to domain.PublicKeyInfo and repo sets it

		err = repo.UpdatePublicKeyStatus(ctx, key1.ID, "REVOKED")
		require.NoError(t, err, "UpdatePublicKeyStatus to REVOKED for key1 should succeed")

		_, err = repo.GetPublicKey(ctx, key1.ID) // Should not be found by GetPublicKey (which implies active)
		assert.Error(t, err, "GetPublicKey for key1 (now REVOKED) should fail")
		assert.Contains(t, err.Error(), "public key not found or not active")
	})

	t.Run("UpdatePublicKeyStatus_NotFound", func(t *testing.T) {
		err := repo.UpdatePublicKeyStatus(ctx, "non-existent-key-for-update", "ACTIVE")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "public key not found for status update")
	})

	t.Run("ListPublicKeysForServiceAccount", func(t *testing.T) {
		// saID1 has key2 (now ACTIVE) and key1 (now REVOKED)
		// saID2 has key3 (ACTIVE)

		// List all for saID1
		keysSA1All, err := repo.ListPublicKeysForServiceAccount(ctx, saID1, false)
		require.NoError(t, err)
		assert.Len(t, keysSA1All, 2, "Should be 2 keys for saID1 (one active, one revoked)")

		// List only active for saID1
		keysSA1Active, err := repo.ListPublicKeysForServiceAccount(ctx, saID1, true)
		require.NoError(t, err)
		assert.Len(t, keysSA1Active, 1, "Should be 1 active key for saID1")
		if len(keysSA1Active) == 1 {
			assert.Equal(t, key2.ID, keysSA1Active[0].ID) // key2 was made active
		}

		// List active for saID2
		keysSA2Active, err := repo.ListPublicKeysForServiceAccount(ctx, saID2, true)
		require.NoError(t, err)
		assert.Len(t, keysSA2Active, 1)
		if len(keysSA2Active) == 1 {
			assert.Equal(t, key3.ID, keysSA2Active[0].ID)
		}

		// List for non-existent SA
		keysNonExistentSA, err := repo.ListPublicKeysForServiceAccount(ctx, "non-existent-sa-id", true)
		require.NoError(t, err)
		assert.Empty(t, keysNonExistentSA, "Should be no keys for non-existent SA")
	})
}
