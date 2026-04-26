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

// Helper function to setup DB for UserSessionStore tests
func setupUserSessionStoreTest(t *testing.T) (domain.UserSessionStore, func(), error) {
	mongoURI := os.Getenv("MONGO_TEST_URI")
	if mongoURI == "" {
		mongoURI = "mongodb://localhost:27017"
	}
	dbName := fmt.Sprintf("test_sso_user_session_%d", time.Now().UnixNano())

	ctx, cancelSetup := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancelSetup()

	// Direct client connection for test isolation
	client, err := mongo.Connect(options.Client().ApplyURI(mongoURI).SetConnectTimeout(10 * time.Second))
	if err != nil {
		return nil, func() {}, fmt.Errorf("mongo.Connect failed for user session store test: %w", err)
	}
	if errPing := client.Ping(ctx, nil); errPing != nil {
		client.Disconnect(ctx)
		return nil, func() {}, fmt.Errorf("mongo.Ping failed for user session store test: %w", errPing)
	}
	db := client.Database(dbName)

	store := mongodb.NewUserSessionStore(db) // Creates collection and TTL index

	cleanupFunc := func() {
		mainCtx := context.Background()
		if errDbDrop := db.Drop(mainCtx); errDbDrop != nil {
			t.Logf("Warning: failed to drop database %s during cleanup: %v", dbName, errDbDrop)
		}
		if errDisconnect := client.Disconnect(mainCtx); errDisconnect != nil {
			t.Logf("Warning: failed to disconnect test client during cleanup: %v", errDisconnect)
		}
	}
	return store, cleanupFunc, nil
}

func TestUserSessionStore_Integration(t *testing.T) {
	if os.Getenv("MONGO_TEST_URI") == "" {
		t.Skip("Skipping MongoDB integration test: MONGO_TEST_URI not set")
	}

	store, cleanup, err := setupUserSessionStoreTest(t)
	require.NoError(t, err, "Failed to setup UserSessionStore test")
	defer cleanup()

	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Millisecond)

	userID1 := "user-session-test-user-1"
	userID2 := "user-session-test-user-2"

	session1 := &domain.UserSession{
		// SessionID intentionally left empty — should be auto-generated
		UserID:          userID1,
		AuthenticatedAt: now,
		ExpiresAt:       now.Add(1 * time.Hour),
		UserAgent:       "Mozilla/5.0 TestAgent1",
		IPAddress:       "192.168.1.1",
	}
	session2 := &domain.UserSession{
		// SessionID intentionally left empty — should be auto-generated
		UserID:          userID1,
		AuthenticatedAt: now,
		ExpiresAt:       now.Add(2 * time.Hour),
		UserAgent:       "Mozilla/5.0 TestAgent2",
		IPAddress:       "192.168.1.2",
	}
	session3Expired := &domain.UserSession{
		// SessionID intentionally left empty — should be auto-generated
		UserID:          userID2,
		AuthenticatedAt: now.Add(-2 * time.Hour),
		ExpiresAt:       now.Add(-1 * time.Hour), // Already expired
		UserAgent:       "Mozilla/5.0 TestAgent3",
		IPAddress:       "192.168.1.3",
	}

	t.Run("StoreUserSessionAndGet", func(t *testing.T) {
		// Store session1 with empty SessionID — verify auto-generation
		err := store.StoreUserSession(ctx, session1)
		require.NoError(t, err, "StoreUserSession for session1 should succeed")
		require.NotEmpty(t, session1.SessionID, "session1 SessionID should be auto-generated")
		assert.Len(t, session1.SessionID, 36, "SessionID should be a UUID (36 chars)")

		// Store session2 with empty SessionID — verify auto-generation
		err = store.StoreUserSession(ctx, session2)
		require.NoError(t, err, "StoreUserSession for session2 should succeed")
		require.NotEmpty(t, session2.SessionID, "session2 SessionID should be auto-generated")

		// Store the expired session
		err = store.StoreUserSession(ctx, session3Expired)
		require.NoError(t, err, "StoreUserSession for session3Expired should succeed")
		require.NotEmpty(t, session3Expired.SessionID, "session3Expired SessionID should be auto-generated")

		// Retrieve session1 by ID — happy path
		fetchedSession, err := store.GetUserSession(ctx, session1.SessionID)
		require.NoError(t, err, "GetUserSession for session1 should succeed")
		require.NotNil(t, fetchedSession)
		assert.Equal(t, session1.SessionID, fetchedSession.SessionID)
		assert.Equal(t, session1.UserID, fetchedSession.UserID)
		assert.Equal(t, session1.UserAgent, fetchedSession.UserAgent)
		assert.Equal(t, session1.IPAddress, fetchedSession.IPAddress)
		assert.WithinDuration(t, session1.AuthenticatedAt, fetchedSession.AuthenticatedAt, time.Second)
		assert.WithinDuration(t, session1.ExpiresAt, fetchedSession.ExpiresAt, time.Second)
	})

	t.Run("GetUserSession_NotFound", func(t *testing.T) {
		_, err := store.GetUserSession(ctx, "non-existent-session-id")
		assert.Error(t, err)
		assert.ErrorIs(t, err, domain.ErrSessionNotFound)
	})

	t.Run("GetUserSession_Expired", func(t *testing.T) {
		// session3Expired has ExpiresAt in the past
		fetchedSession, err := store.GetUserSession(ctx, session3Expired.SessionID)
		// Should return the session alongside the expired error
		require.NotNil(t, fetchedSession, "Expired session should still be returned")
		assert.Equal(t, session3Expired.SessionID, fetchedSession.SessionID)
		assert.Equal(t, session3Expired.UserID, fetchedSession.UserID)
		assert.ErrorIs(t, err, domain.ErrSessionExpired)
	})

	t.Run("DeleteUserSession", func(t *testing.T) {
		// Store a fresh session specifically for deletion test
		sessionToDelete := &domain.UserSession{
			UserID:          userID2,
			AuthenticatedAt: now,
			ExpiresAt:       now.Add(1 * time.Hour),
			UserAgent:       "Mozilla/5.0 DeleteAgent",
			IPAddress:       "10.0.0.1",
		}
		err := store.StoreUserSession(ctx, sessionToDelete)
		require.NoError(t, err, "StoreUserSession for deletion target should succeed")
		require.NotEmpty(t, sessionToDelete.SessionID)

		// Delete the session
		err = store.DeleteUserSession(ctx, sessionToDelete.SessionID)
		require.NoError(t, err, "DeleteUserSession should succeed")

		// Verify it is gone
		_, err = store.GetUserSession(ctx, sessionToDelete.SessionID)
		assert.Error(t, err)
		assert.ErrorIs(t, err, domain.ErrSessionNotFound)
	})

	t.Run("DeleteUserSession_NotFound", func(t *testing.T) {
		err := store.DeleteUserSession(ctx, "does-not-exist")
		assert.Error(t, err)
		assert.ErrorIs(t, err, domain.ErrSessionNotFound)
	})

	t.Run("CleanupExpiredSessions", func(t *testing.T) {
		// This is a no-op method; just ensure it doesn't panic
		require.NotPanics(t, func() {
			store.CleanupExpiredSessions()
		}, "CleanupExpiredSessions should not panic")
	})
}
