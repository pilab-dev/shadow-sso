package mongodb_test

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/pilab-dev/shadow-sso/domain"
	"github.com/pilab-dev/shadow-sso/mongodb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

func setupRealmSettingsTest(t *testing.T) (*mongodb.RealmSettingsRepository, func(), error) {
	mongoURI := os.Getenv("MONGO_TEST_URI")
	if mongoURI == "" {
		mongoURI = "mongodb://localhost:27017"
	}
	dbName := fmt.Sprintf("test_sso_realm_settings_%d", time.Now().UnixNano())

	ctx, cancelSetup := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancelSetup()

	client, err := mongo.Connect(options.Client().ApplyURI(mongoURI).SetConnectTimeout(10 * time.Second))
	if err != nil {
		return nil, func() {}, fmt.Errorf("mongo.Connect failed for realm settings test: %w", err)
	}
	if errPing := client.Ping(ctx, nil); errPing != nil {
		client.Disconnect(ctx)
		return nil, func() {}, fmt.Errorf("mongo.Ping failed for realm settings test: %w", errPing)
	}
	db := client.Database(dbName)

	repoIf, err := mongodb.NewRealmSettingsRepository(ctx, db)
	if err != nil {
		client.Disconnect(ctx)
		return nil, func() {}, fmt.Errorf("NewRealmSettingsRepository failed: %w", err)
	}
	repo, ok := repoIf.(*mongodb.RealmSettingsRepository)
	if !ok {
		client.Disconnect(ctx)
		return nil, func() {}, fmt.Errorf("NewRealmSettingsRepository returned unexpected type %T", repoIf)
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
	return repo, cleanupFunc, nil
}

func TestRealmSettingsRepository_SeedRealmSettingsIfEmpty(t *testing.T) {
	if os.Getenv("MONGO_TEST_URI") == "" {
		t.Skip("Skipping MongoDB integration test: MONGO_TEST_URI not set")
	}

	repo, cleanup, err := setupRealmSettingsTest(t)
	require.NoError(t, err, "Failed to setup RealmSettingsRepository test")
	defer cleanup()

	ctx := context.Background()

	seed := &domain.RealmSettings{
		Realm:               "master",
		DisplayName:         "Shadow SSO",
		Enabled:             true,
		BruteForceProtected: true,
		AccessTokenLifespan: 900,
		AccessCodeLifespan:  600,
	}

	t.Run("SeedsOnEmptyCollection", func(t *testing.T) {
		seeded, err := repo.SeedRealmSettingsIfEmpty(ctx, seed)
		require.NoError(t, err)
		assert.True(t, seeded, "expected settings to be seeded on a fresh collection")

		got, err := repo.GetRealmSettings(ctx)
		require.NoError(t, err)
		assert.Equal(t, "master", got.Realm)
		assert.Equal(t, 900, got.AccessTokenLifespan)
		assert.Equal(t, 600, got.AccessCodeLifespan)
	})

	t.Run("SkipsWhenAlreadySeeded", func(t *testing.T) {
		override := &domain.RealmSettings{
			Realm:               "master",
			DisplayName:         "Shadow SSO",
			Enabled:             true,
			BruteForceProtected: true,
			AccessTokenLifespan: 120,
			AccessCodeLifespan:  30,
		}
		seeded, err := repo.SeedRealmSettingsIfEmpty(ctx, override)
		require.NoError(t, err)
		assert.False(t, seeded, "expected no re-seed when settings already exist")

		got, err := repo.GetRealmSettings(ctx)
		require.NoError(t, err)
		assert.Equal(t, 900, got.AccessTokenLifespan, "existing settings must not be clobbered")
	})
}
