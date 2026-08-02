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

// Helper function to setup DB for FlowStore tests
func setupFlowStoreTest(t *testing.T) (domain.FlowStore, func(), error) {
	mongoURI := os.Getenv("MONGO_TEST_URI")
	if mongoURI == "" {
		mongoURI = "mongodb://localhost:27017"
	}
	dbName := fmt.Sprintf("test_sso_flow_%d", time.Now().UnixNano())

	ctx, cancelSetup := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancelSetup()

	client, err := mongo.Connect(options.Client().ApplyURI(mongoURI).SetConnectTimeout(10 * time.Second))
	if err != nil {
		return nil, func() {}, fmt.Errorf("mongo.Connect failed for flow store test: %w", err)
	}
	if errPing := client.Ping(ctx, nil); errPing != nil {
		client.Disconnect(ctx)
		return nil, func() {}, fmt.Errorf("mongo.Ping failed for flow store test: %w", errPing)
	}
	db := client.Database(dbName)

	flowStore := mongodb.NewFlowStore(ctx, db) // Creates collection and TTL index

	cleanupFunc := func() {
		mainCtx := context.Background()
		if errDbDrop := db.Drop(mainCtx); errDbDrop != nil {
			t.Logf("Warning: failed to drop database %s during cleanup: %v", dbName, errDbDrop)
		}
		if errDisconnect := client.Disconnect(mainCtx); errDisconnect != nil {
			t.Logf("Warning: failed to disconnect test client during cleanup: %v", errDisconnect)
		}
	}
	return flowStore, cleanupFunc, nil
}

func TestFlowStore_Integration(t *testing.T) {
	if os.Getenv("MONGO_TEST_URI") == "" {
		t.Skip("Skipping MongoDB integration test: MONGO_TEST_URI not set")
	}

	store, cleanup, err := setupFlowStoreTest(t)
	require.NoError(t, err, "Failed to setup FlowStore test")
	defer cleanup()

	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Millisecond)

	flowID1 := "flow-id-1"
	flowID2 := "flow-id-2"
	flowID3 := "flow-id-3"

	flowState1 := domain.LoginFlowState{
		FlowID:              flowID1,
		ClientID:            "test-client-id",
		RedirectURI:         "https://client.example.com/callback",
		Scope:               "openid profile email",
		State:               "client-state-123",
		Nonce:               "nonce-abc",
		CodeChallenge:       "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
		CodeChallengeMethod: "S256",
		UserID:              "user-456",
		UserAuthenticatedAt: now,
		ExpiresAt:           now.Add(1 * time.Hour),
		OriginalOIDCParams: map[string]string{
			"prompt": "consent",
		},
	}

	flowState2 := domain.LoginFlowState{
		FlowID:              flowID2,
		ClientID:            "another-client-id",
		RedirectURI:         "https://another.example.com/callback",
		Scope:               "openid",
		State:               "client-state-456",
		ExpiresAt:           now.Add(30 * time.Minute),
		OriginalOIDCParams:  map[string]string{},
	}

	flowStateExpired := domain.LoginFlowState{
		FlowID:              flowID3,
		ClientID:            "expired-client-id",
		RedirectURI:         "https://expired.example.com/callback",
		Scope:               "openid",
		State:               "client-state-expired",
		ExpiresAt:           now.Add(-1 * time.Hour), // Already expired
		OriginalOIDCParams:  map[string]string{},
	}

	t.Run("StoreFlowAndGetFlow", func(t *testing.T) {
		err := store.StoreFlow(ctx, flowID1, flowState1)
		require.NoError(t, err, "StoreFlow for flowState1 should succeed")

		fetchedFlow, err := store.GetFlow(ctx, flowID1)
		require.NoError(t, err, "GetFlow for flowID1 should succeed")
		require.NotNil(t, fetchedFlow)
		assert.Equal(t, flowState1.FlowID, fetchedFlow.FlowID)
		assert.Equal(t, flowState1.ClientID, fetchedFlow.ClientID)
		assert.Equal(t, flowState1.RedirectURI, fetchedFlow.RedirectURI)
		assert.Equal(t, flowState1.Scope, fetchedFlow.Scope)
		assert.Equal(t, flowState1.State, fetchedFlow.State)
		assert.Equal(t, flowState1.Nonce, fetchedFlow.Nonce)
		assert.Equal(t, flowState1.CodeChallenge, fetchedFlow.CodeChallenge)
		assert.Equal(t, flowState1.CodeChallengeMethod, fetchedFlow.CodeChallengeMethod)
		assert.Equal(t, flowState1.UserID, fetchedFlow.UserID)
		assert.WithinDuration(t, flowState1.UserAuthenticatedAt, fetchedFlow.UserAuthenticatedAt, time.Second)
		assert.WithinDuration(t, flowState1.ExpiresAt, fetchedFlow.ExpiresAt, time.Second)
		assert.Equal(t, flowState1.OriginalOIDCParams, fetchedFlow.OriginalOIDCParams)

		// Store and retrieve a second flow
		err = store.StoreFlow(ctx, flowID2, flowState2)
		require.NoError(t, err, "StoreFlow for flowState2 should succeed")

		fetchedFlow2, err := store.GetFlow(ctx, flowID2)
		require.NoError(t, err, "GetFlow for flowID2 should succeed")
		require.NotNil(t, fetchedFlow2)
		assert.Equal(t, flowState2.FlowID, fetchedFlow2.FlowID)
		assert.Equal(t, flowState2.ClientID, fetchedFlow2.ClientID)
		assert.WithinDuration(t, flowState2.ExpiresAt, fetchedFlow2.ExpiresAt, time.Second)
	})

	t.Run("GetFlow_NotFound", func(t *testing.T) {
		fetchedFlow, err := store.GetFlow(ctx, "non-existent-flow-id")
		assert.Error(t, err)
		assert.ErrorIs(t, err, domain.ErrFlowNotFound)
		assert.Nil(t, fetchedFlow)
	})

	t.Run("GetFlow_Expired", func(t *testing.T) {
		err := store.StoreFlow(ctx, flowID3, flowStateExpired)
		require.NoError(t, err, "StoreFlow for expired flow should succeed")

		fetchedFlow, err := store.GetFlow(ctx, flowID3)
		require.Error(t, err, "GetFlow for expired flow should return an error")
		assert.ErrorIs(t, err, domain.ErrFlowExpired)
		// The state is still returned alongside ErrFlowExpired
		require.NotNil(t, fetchedFlow, "GetFlow should return the state even when expired")
		assert.Equal(t, flowStateExpired.FlowID, fetchedFlow.FlowID)
		assert.Equal(t, flowStateExpired.ClientID, fetchedFlow.ClientID)
	})

	t.Run("UpdateFlow", func(t *testing.T) {
		// flowState1 already stored; update its UserID and UserAuthenticatedAt
		updatedState := flowState1
		updatedState.UserID = "updated-user-789"
		updatedState.UserAuthenticatedAt = now.Add(5 * time.Minute)

		err := store.UpdateFlow(ctx, flowID1, &updatedState)
		require.NoError(t, err, "UpdateFlow should succeed")

		fetchedFlow, err := store.GetFlow(ctx, flowID1)
		require.NoError(t, err)
		require.NotNil(t, fetchedFlow)
		assert.Equal(t, "updated-user-789", fetchedFlow.UserID)
		assert.WithinDuration(t, now.Add(5*time.Minute), fetchedFlow.UserAuthenticatedAt, time.Second)
		// Ensure other fields remain unchanged
		assert.Equal(t, flowState1.ClientID, fetchedFlow.ClientID)
		assert.Equal(t, flowState1.Scope, fetchedFlow.Scope)
	})

	t.Run("UpdateFlow_NotFound", func(t *testing.T) {
		nonExistent := flowState1
		nonExistent.FlowID = "non-existent-flow-id"

		err := store.UpdateFlow(ctx, "non-existent-flow-id", &nonExistent)
		assert.Error(t, err)
		assert.ErrorIs(t, err, domain.ErrFlowNotFound)
	})

	t.Run("DeleteFlow", func(t *testing.T) {
		// flowState2 exists; delete it
		err := store.DeleteFlow(ctx, flowID2)
		require.NoError(t, err, "DeleteFlow should succeed")

		// Verify it's gone
		fetchedFlow, err := store.GetFlow(ctx, flowID2)
		assert.Error(t, err)
		assert.ErrorIs(t, err, domain.ErrFlowNotFound)
		assert.Nil(t, fetchedFlow)
	})

	t.Run("DeleteFlow_NotFound", func(t *testing.T) {
		err := store.DeleteFlow(ctx, "non-existent-flow-id")
		assert.Error(t, err)
		assert.ErrorIs(t, err, domain.ErrFlowNotFound)
	})

	t.Run("CleanupExpiredFlows", func(t *testing.T) {
		// CleanupExpiredFlows is a no-op (TTL index handles cleanup).
		// Just call it and ensure no panic.
		require.NotPanics(t, func() {
			store.CleanupExpiredFlows()
		})
	})
}
