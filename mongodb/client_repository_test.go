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

func setupClientTest(t *testing.T) (*mongodb.ClientRepository, func(), error) {
	mongoURI := os.Getenv("MONGO_TEST_URI")
	if mongoURI == "" {
		mongoURI = "mongodb://localhost:27017"
	}
	dbName := fmt.Sprintf("test_sso_client_%d", time.Now().UnixNano())

	ctx, cancelSetup := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancelSetup()

	client, err := mongo.Connect(options.Client().ApplyURI(mongoURI).SetConnectTimeout(10 * time.Second))
	if err != nil {
		return nil, func() {}, fmt.Errorf("mongo.Connect failed for client test: %w", err)
	}
	if errPing := client.Ping(ctx, nil); errPing != nil {
		client.Disconnect(ctx)
		return nil, func() {}, fmt.Errorf("mongo.Ping failed for client test: %w", errPing)
	}
	db := client.Database(dbName)

	repo := mongodb.NewClientRepository(ctx, db)

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

func insertClients(t *testing.T, repo *mongodb.ClientRepository, clients []*domain.Client) {
	t.Helper()
	for _, c := range clients {
		require.NoError(t, repo.CreateClient(context.Background(), c))
	}
}

func clientIDs(got []*domain.Client) []string {
	var out []string
	for _, c := range got {
		out = append(out, c.ID)
	}
	return out
}

func TestClientRepository_ListClientsPage_Filters(t *testing.T) {
	if os.Getenv("MONGO_TEST_URI") == "" {
		t.Skip("Skipping MongoDB integration test: MONGO_TEST_URI not set")
	}

	repo, cleanup, err := setupClientTest(t)
	require.NoError(t, err, "Failed to setup ClientRepository test")
	defer cleanup()

	ctx := context.Background()
	insertClients(t, repo, []*domain.Client{
		{ID: "alpha", Name: "Web App", Type: domain.ClientTypeConfidential, IsActive: true},
		{ID: "beta", Name: "Mobile App", Type: domain.ClientTypePublic, IsActive: true},
		{ID: "gamma", Name: "API Gateway", Type: domain.ClientTypeConfidential, IsActive: false},
	})

	t.Run("by exact client id", func(t *testing.T) {
		got, total, err := repo.ListClientsPage(ctx, domain.ClientFilter{ClientID: "beta"}, 0, 10)
		require.NoError(t, err)
		assert.Equal(t, int64(1), total)
		assert.Equal(t, []string{"beta"}, clientIDs(got))
	})

	t.Run("by client name regex case-insensitive", func(t *testing.T) {
		got, total, err := repo.ListClientsPage(ctx, domain.ClientFilter{ClientName: "app"}, 0, 10)
		require.NoError(t, err)
		assert.Equal(t, int64(2), total)
		assert.Equal(t, []string{"alpha", "beta"}, clientIDs(got))
	})

	t.Run("by enabled", func(t *testing.T) {
		got, total, err := repo.ListClientsPage(ctx, domain.ClientFilter{Enabled: boolPtr(true)}, 0, 10)
		require.NoError(t, err)
		assert.Equal(t, int64(2), total)
		assert.Equal(t, []string{"alpha", "beta"}, clientIDs(got))

		got, total, err = repo.ListClientsPage(ctx, domain.ClientFilter{Enabled: boolPtr(false)}, 0, 10)
		require.NoError(t, err)
		assert.Equal(t, int64(1), total)
		assert.Equal(t, []string{"gamma"}, clientIDs(got))
	})

	t.Run("by public client", func(t *testing.T) {
		got, total, err := repo.ListClientsPage(ctx, domain.ClientFilter{PublicClient: boolPtr(true)}, 0, 10)
		require.NoError(t, err)
		assert.Equal(t, int64(1), total)
		assert.Equal(t, []string{"beta"}, clientIDs(got))

		got, total, err = repo.ListClientsPage(ctx, domain.ClientFilter{PublicClient: boolPtr(false)}, 0, 10)
		require.NoError(t, err)
		assert.Equal(t, int64(2), total)
		assert.Equal(t, []string{"alpha", "gamma"}, clientIDs(got))
	})

	t.Run("by search across client id and name", func(t *testing.T) {
		got, total, err := repo.ListClientsPage(ctx, domain.ClientFilter{Search: "alpha"}, 0, 10)
		require.NoError(t, err)
		assert.Equal(t, int64(1), total)
		assert.Equal(t, []string{"alpha"}, clientIDs(got))

		got, total, err = repo.ListClientsPage(ctx, domain.ClientFilter{Search: "web"}, 0, 10)
		require.NoError(t, err)
		assert.Equal(t, int64(1), total)
		assert.Equal(t, []string{"alpha"}, clientIDs(got))

		got, total, err = repo.ListClientsPage(ctx, domain.ClientFilter{Search: "GATEWAY"}, 0, 10)
		require.NoError(t, err)
		assert.Equal(t, int64(1), total)
		assert.Equal(t, []string{"gamma"}, clientIDs(got))
	})
}

func TestClientRepository_ListClientsPage_Sort(t *testing.T) {
	if os.Getenv("MONGO_TEST_URI") == "" {
		t.Skip("Skipping MongoDB integration test: MONGO_TEST_URI not set")
	}

	repo, cleanup, err := setupClientTest(t)
	require.NoError(t, err, "Failed to setup ClientRepository test")
	defer cleanup()

	ctx := context.Background()
	insertClients(t, repo, []*domain.Client{
		{ID: "c-client", Name: "cherry"},
		{ID: "a-client", Name: "apple"},
		{ID: "b-client", Name: "banana"},
	})

	t.Run("clientId asc", func(t *testing.T) {
		got, _, err := repo.ListClientsPage(ctx, domain.ClientFilter{SortBy: "clientId", SortDir: "asc"}, 0, 10)
		require.NoError(t, err)
		assert.Equal(t, []string{"a-client", "b-client", "c-client"}, clientIDs(got))
	})

	t.Run("clientId desc", func(t *testing.T) {
		got, _, err := repo.ListClientsPage(ctx, domain.ClientFilter{SortBy: "clientId", SortDir: "desc"}, 0, 10)
		require.NoError(t, err)
		assert.Equal(t, []string{"c-client", "b-client", "a-client"}, clientIDs(got))
	})

	t.Run("clientName asc", func(t *testing.T) {
		got, _, err := repo.ListClientsPage(ctx, domain.ClientFilter{SortBy: "clientName", SortDir: "asc"}, 0, 10)
		require.NoError(t, err)
		assert.Equal(t, []string{"a-client", "b-client", "c-client"}, clientIDs(got))
	})

	t.Run("clientName desc", func(t *testing.T) {
		got, _, err := repo.ListClientsPage(ctx, domain.ClientFilter{SortBy: "clientName", SortDir: "desc"}, 0, 10)
		require.NoError(t, err)
		assert.Equal(t, []string{"c-client", "b-client", "a-client"}, clientIDs(got))
	})

	t.Run("unknown sort falls back to default", func(t *testing.T) {
		got, _, err := repo.ListClientsPage(ctx, domain.ClientFilter{SortBy: "bogus", SortDir: "asc"}, 0, 10)
		require.NoError(t, err)
		assert.Equal(t, []string{"a-client", "b-client", "c-client"}, clientIDs(got),
			"unknown sort key keeps client_id asc ordering")
	})
}

func TestClientRepository_ListClientsPage_PaginationAndCount(t *testing.T) {
	if os.Getenv("MONGO_TEST_URI") == "" {
		t.Skip("Skipping MongoDB integration test: MONGO_TEST_URI not set")
	}

	repo, cleanup, err := setupClientTest(t)
	require.NoError(t, err, "Failed to setup ClientRepository test")
	defer cleanup()

	ctx := context.Background()
	insertClients(t, repo, []*domain.Client{
		{ID: "a-client", Name: "apple", IsActive: true},
		{ID: "b-client", Name: "banana", IsActive: false},
		{ID: "c-client", Name: "cherry", IsActive: true},
		{ID: "d-client", Name: "date", IsActive: true},
		{ID: "e-client", Name: "elderberry", IsActive: false},
	})

	t.Run("total counts all matching", func(t *testing.T) {
		_, total, err := repo.ListClientsPage(ctx, domain.ClientFilter{}, 0, 10)
		require.NoError(t, err)
		assert.Equal(t, int64(5), total)
	})

	t.Run("count honors the filter", func(t *testing.T) {
		_, total, err := repo.ListClientsPage(ctx, domain.ClientFilter{Enabled: boolPtr(true)}, 0, 10)
		require.NoError(t, err)
		assert.Equal(t, int64(3), total)

		_, total, err = repo.ListClientsPage(ctx, domain.ClientFilter{ClientID: "missing"}, 0, 10)
		require.NoError(t, err)
		assert.Equal(t, int64(0), total)
	})

	t.Run("pages walk the whole set", func(t *testing.T) {
		var all []string
		for skip := 0; skip < 5; skip += 2 {
			got, total, err := repo.ListClientsPage(ctx, domain.ClientFilter{}, skip, 2)
			require.NoError(t, err)
			assert.Equal(t, int64(5), total)
			all = append(all, clientIDs(got)...)
		}
		assert.Equal(t, []string{"a-client", "b-client", "c-client", "d-client", "e-client"}, all,
			"default sort client_id asc walks the set in order")
	})

	t.Run("limit beyond the set returns what remains", func(t *testing.T) {
		got, total, err := repo.ListClientsPage(ctx, domain.ClientFilter{}, 4, 10)
		require.NoError(t, err)
		assert.Equal(t, int64(5), total)
		assert.Equal(t, []string{"e-client"}, clientIDs(got))
	})
}

func boolPtr(b bool) *bool {
	return &b
}
