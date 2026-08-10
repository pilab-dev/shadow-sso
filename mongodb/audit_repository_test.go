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

func setupAuditTest(t *testing.T) (*mongodb.AuditRepository, func(), error) {
	mongoURI := os.Getenv("MONGO_TEST_URI")
	if mongoURI == "" {
		mongoURI = "mongodb://localhost:27017"
	}
	dbName := fmt.Sprintf("test_sso_audit_%d", time.Now().UnixNano())

	ctx, cancelSetup := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancelSetup()

	client, err := mongo.Connect(options.Client().ApplyURI(mongoURI).SetConnectTimeout(10 * time.Second))
	if err != nil {
		return nil, func() {}, fmt.Errorf("mongo.Connect failed for audit test: %w", err)
	}
	if errPing := client.Ping(ctx, nil); errPing != nil {
		client.Disconnect(ctx)
		return nil, func() {}, fmt.Errorf("mongo.Ping failed for audit test: %w", errPing)
	}
	db := client.Database(dbName)

	repoIf, err := mongodb.NewAuditRepository(ctx, db)
	if err != nil {
		client.Disconnect(ctx)
		return nil, func() {}, fmt.Errorf("NewAuditRepository failed: %w", err)
	}
	repo, ok := repoIf.(*mongodb.AuditRepository)
	if !ok {
		client.Disconnect(ctx)
		return nil, func() {}, fmt.Errorf("NewAuditRepository returned unexpected type %T", repoIf)
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

func TestAuditRepository_InsertAssignsIDAndDefaultsTimestamp(t *testing.T) {
	if os.Getenv("MONGO_TEST_URI") == "" {
		t.Skip("Skipping MongoDB integration test: MONGO_TEST_URI not set")
	}

	repo, cleanup, err := setupAuditTest(t)
	require.NoError(t, err, "Failed to setup AuditRepository test")
	defer cleanup()

	event := &domain.AuditLog{
		Service: "user",
		Action:  "create",
		User:    "u1",
		Success: true,
	}
	require.NoError(t, repo.Insert(context.Background(), event))
	assert.NotEmpty(t, event.ID, "Insert should assign an ID")
	assert.False(t, event.Timestamp.IsZero(), "Insert should default the timestamp")
}

func TestAuditRepository_ListOrderingAndPagination(t *testing.T) {
	if os.Getenv("MONGO_TEST_URI") == "" {
		t.Skip("Skipping MongoDB integration test: MONGO_TEST_URI not set")
	}

	repo, cleanup, err := setupAuditTest(t)
	require.NoError(t, err, "Failed to setup AuditRepository test")
	defer cleanup()

	ctx := context.Background()
	base := time.Now().UTC().Add(-time.Hour)
	events := []*domain.AuditLog{
		{Service: "user", Action: "create", User: "u1", Timestamp: base.Add(time.Minute)},
		{Service: "user", Action: "update", User: "u1", Timestamp: base.Add(2 * time.Minute)},
		{Service: "client", Action: "delete", User: "admin", Timestamp: base.Add(3 * time.Minute)},
	}
	for _, e := range events {
		require.NoError(t, repo.Insert(ctx, e))
	}

	got, err := repo.List(ctx, domain.AuditLogFilter{}, 10, 0)
	require.NoError(t, err)
	require.Len(t, got, 3)
	assert.Equal(t, events[2].ID, got[0].ID, "newest event first")
	assert.Equal(t, events[1].ID, got[1].ID)
	assert.Equal(t, events[0].ID, got[2].ID)

	page, err := repo.List(ctx, domain.AuditLogFilter{}, 1, 1)
	require.NoError(t, err)
	require.Len(t, page, 1)
	assert.Equal(t, events[1].ID, page[0].ID, "offset skips the newest event")
}

func TestAuditRepository_ListFilters(t *testing.T) {
	if os.Getenv("MONGO_TEST_URI") == "" {
		t.Skip("Skipping MongoDB integration test: MONGO_TEST_URI not set")
	}

	repo, cleanup, err := setupAuditTest(t)
	require.NoError(t, err, "Failed to setup AuditRepository test")
	defer cleanup()

	ctx := context.Background()
	base := time.Now().UTC().Add(-time.Hour)
	events := []*domain.AuditLog{
		{Service: "user", Action: "create", User: "u1", Timestamp: base.Add(time.Minute)},
		{Service: "user", Action: "update", User: "u1", Timestamp: base.Add(2 * time.Minute)},
		{Service: "client", Action: "delete", User: "admin", Timestamp: base.Add(3 * time.Minute)},
	}
	for _, e := range events {
		require.NoError(t, repo.Insert(ctx, e))
	}

	t.Run("by user", func(t *testing.T) {
		got, err := repo.List(ctx, domain.AuditLogFilter{User: "u1"}, 10, 0)
		require.NoError(t, err)
		require.Len(t, got, 2)
		for _, e := range got {
			assert.Equal(t, "u1", e.User)
		}
	})

	t.Run("by action", func(t *testing.T) {
		got, err := repo.List(ctx, domain.AuditLogFilter{Action: "delete"}, 10, 0)
		require.NoError(t, err)
		require.Len(t, got, 1)
		assert.Equal(t, "delete", got[0].Action)
	})

	t.Run("by time window", func(t *testing.T) {
		from := base.Add(90 * time.Second)
		to := base.Add(150 * time.Second)
		got, err := repo.List(ctx, domain.AuditLogFilter{From: &from, To: &to}, 10, 0)
		require.NoError(t, err)
		require.Len(t, got, 1)
		assert.Equal(t, "update", got[0].Action)
	})
}

func TestAuditRepository_ListSort(t *testing.T) {
	if os.Getenv("MONGO_TEST_URI") == "" {
		t.Skip("Skipping MongoDB integration test: MONGO_TEST_URI not set")
	}

	repo, cleanup, err := setupAuditTest(t)
	require.NoError(t, err, "Failed to setup AuditRepository test")
	defer cleanup()

	ctx := context.Background()
	base := time.Now().UTC().Add(-time.Hour)
	events := []*domain.AuditLog{
		{Service: "user", Action: "create", User: "alice", Timestamp: base.Add(time.Minute)},
		{Service: "user", Action: "update", User: "bob", Timestamp: base.Add(2 * time.Minute)},
		{Service: "client", Action: "delete", User: "carol", Timestamp: base.Add(3 * time.Minute)},
	}
	for _, e := range events {
		require.NoError(t, repo.Insert(ctx, e))
	}

	ids := func(got []*domain.AuditLog) []string {
		var out []string
		for _, e := range got {
			out = append(out, e.ID)
		}
		return out
	}

	t.Run("action asc", func(t *testing.T) {
		got, err := repo.List(ctx, domain.AuditLogFilter{SortBy: "action", SortDir: "asc"}, 10, 0)
		require.NoError(t, err)
		assert.Equal(t, []string{events[0].ID, events[2].ID, events[1].ID}, ids(got),
			"actions sorted alphabetically: create, delete, update")
	})

	t.Run("action desc", func(t *testing.T) {
		got, err := repo.List(ctx, domain.AuditLogFilter{SortBy: "action", SortDir: "desc"}, 10, 0)
		require.NoError(t, err)
		assert.Equal(t, []string{events[1].ID, events[2].ID, events[0].ID}, ids(got),
			"actions sorted reverse alphabetically: update, delete, create")
	})

	t.Run("actor asc", func(t *testing.T) {
		got, err := repo.List(ctx, domain.AuditLogFilter{SortBy: "actor", SortDir: "asc"}, 10, 0)
		require.NoError(t, err)
		assert.Equal(t, []string{events[0].ID, events[1].ID, events[2].ID}, ids(got),
			"actors sorted alphabetically: alice, bob, carol")
	})

	t.Run("created_at desc", func(t *testing.T) {
		got, err := repo.List(ctx, domain.AuditLogFilter{SortBy: "created_at", SortDir: "desc"}, 10, 0)
		require.NoError(t, err)
		assert.Equal(t, []string{events[2].ID, events[1].ID, events[0].ID}, ids(got),
			"newest event first")
	})

	t.Run("unknown field falls back to default", func(t *testing.T) {
		got, err := repo.List(ctx, domain.AuditLogFilter{SortBy: "bogus", SortDir: "asc"}, 10, 0)
		require.NoError(t, err)
		assert.Equal(t, []string{events[2].ID, events[1].ID, events[0].ID}, ids(got),
			"unknown sort key keeps newest-first ordering")
	})
}

func TestAuditRepository_CountRespectsFilter(t *testing.T) {
	if os.Getenv("MONGO_TEST_URI") == "" {
		t.Skip("Skipping MongoDB integration test: MONGO_TEST_URI not set")
	}

	repo, cleanup, err := setupAuditTest(t)
	require.NoError(t, err, "Failed to setup AuditRepository test")
	defer cleanup()

	ctx := context.Background()
	base := time.Now().UTC().Add(-time.Hour)
	for _, e := range []*domain.AuditLog{
		{Service: "user", Action: "create", User: "u1", Timestamp: base.Add(time.Minute)},
		{Service: "user", Action: "update", User: "u1", Timestamp: base.Add(2 * time.Minute)},
		{Service: "client", Action: "delete", User: "admin", Timestamp: base.Add(3 * time.Minute)},
	} {
		require.NoError(t, repo.Insert(ctx, e))
	}

	total, err := repo.Count(ctx, domain.AuditLogFilter{User: "u1"})
	require.NoError(t, err)
	assert.Equal(t, int64(2), total)

	totalAll, err := repo.Count(ctx, domain.AuditLogFilter{})
	require.NoError(t, err)
	assert.Equal(t, int64(3), totalAll)
}
