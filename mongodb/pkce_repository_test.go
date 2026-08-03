package mongodb_test

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

	"github.com/pilab-dev/shadow-sso/mongodb"
)

// Helper function to setup DB for PkceRepository tests
func setupPkceRepositoryTest(t *testing.T) (domain.PkceRepository, func(), error) {
	mongoURI := os.Getenv("MONGO_TEST_URI")
	if mongoURI == "" {
		mongoURI = "mongodb://localhost:27017"
	}
	dbName := fmt.Sprintf("test_sso_pkce_%d", time.Now().UnixNano())

	ctx, cancelSetup := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancelSetup()

	// Direct client connection for test isolation
	client, err := mongo.Connect(options.Client().ApplyURI(mongoURI).SetConnectTimeout(10 * time.Second))
	if err != nil {
		return nil, func() {}, fmt.Errorf("mongo.Connect failed for pkce repo test: %w", err)
	}
	if errPing := client.Ping(ctx, nil); errPing != nil {
		client.Disconnect(ctx)
		return nil, func() {}, fmt.Errorf("mongo.Ping failed for pkce repo test: %w", errPing)
	}
	db := client.Database(dbName)

	pkceRepo := mongodb.NewPkceRepository(ctx, db) // Creates collection and indexes

	cleanupFunc := func() {
		mainCtx := context.Background()
		if errDbDrop := db.Drop(mainCtx); errDbDrop != nil {
			t.Logf("Warning: failed to drop database %s during cleanup: %v", dbName, errDbDrop)
		}
		if errDisconnect := client.Disconnect(mainCtx); errDisconnect != nil {
			t.Logf("Warning: failed to disconnect test client during cleanup: %v", errDisconnect)
		}
	}
	return pkceRepo, cleanupFunc, nil
}

func TestPkceRepository_Integration(t *testing.T) {
	if os.Getenv("MONGO_TEST_URI") == "" {
		t.Skip("Skipping MongoDB integration test: MONGO_TEST_URI not set")
	}

	repo, cleanup, err := setupPkceRepositoryTest(t)
	require.NoError(t, err, "Failed to setup PkceRepository test")
	defer cleanup()

	ctx := context.Background()

	t.Run("SaveCodeChallengeAndGet", func(t *testing.T) {
		code := "test-auth-code-123"
		challenge := "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

		err := repo.SaveCodeChallenge(ctx, code, challenge)
		require.NoError(t, err, "SaveCodeChallenge should succeed")

		retrieved, err := repo.GetCodeChallenge(ctx, code)
		require.NoError(t, err, "GetCodeChallenge should succeed")
		assert.Equal(t, challenge, retrieved, "Retrieved challenge should match saved value")
	})

	t.Run("GetCodeChallenge_NotFound", func(t *testing.T) {
		_, err := repo.GetCodeChallenge(ctx, "non-existent-code")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "code challenge not found for code: non-existent-code")
	})

	t.Run("DeleteCodeChallenge", func(t *testing.T) {
		code := "test-auth-code-to-delete"
		challenge := "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

		err := repo.SaveCodeChallenge(ctx, code, challenge)
		require.NoError(t, err, "SaveCodeChallenge should succeed")

		err = repo.DeleteCodeChallenge(ctx, code)
		require.NoError(t, err, "DeleteCodeChallenge should succeed")

		_, err = repo.GetCodeChallenge(ctx, code)
		assert.Error(t, err, "GetCodeChallenge should fail after deletion")
		assert.Contains(t, err.Error(), "code challenge not found for code: "+code)
	})

	t.Run("DeleteCodeChallenge_NotFound_Idempotent", func(t *testing.T) {
		// Deleting a non-existent code should NOT error (idempotent)
		err := repo.DeleteCodeChallenge(ctx, "never-saved-code")
		require.NoError(t, err, "DeleteCodeChallenge for non-existent code should be idempotent and not error")
	})
}
