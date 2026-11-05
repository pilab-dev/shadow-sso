package mongodb_test

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/pilab-dev/shadow-sso/domain"
	"github.com/pilab-dev/shadow-sso/mongodb"
	"github.com/stretchr/testify/require"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

func setupProtocolMapperTest(t *testing.T) (*mongodb.ProtocolMapperRepository, *mongo.Database, func()) {
	t.Helper()

	mongoURI := os.Getenv("MONGO_TEST_URI")
	if mongoURI == "" {
		mongoURI = "mongodb://localhost:27017"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	client, err := mongo.Connect(options.Client().ApplyURI(mongoURI).SetConnectTimeout(5 * time.Second))
	if err != nil {
		t.Skipf("MongoDB not available: %v", err)
	}
	if err := client.Ping(ctx, nil); err != nil {
		_ = client.Disconnect(context.Background())
		t.Skipf("MongoDB not available: %v", err)
	}

	dbName := fmt.Sprintf("test_sso_protocol_mappers_%d", time.Now().UnixNano())
	db := client.Database(dbName)

	repoIf, err := mongodb.NewProtocolMapperRepository(ctx, db)
	require.NoError(t, err)
	repo, ok := repoIf.(*mongodb.ProtocolMapperRepository)
	require.True(t, ok)

	cleanup := func() {
		_ = db.Drop(context.Background())
		_ = client.Disconnect(context.Background())
	}
	return repo, db, cleanup
}

// TestProtocolMapperRepository_RealmWideMappersAreApplied pins the Keycloak
// semantics: a mapper without a client id applies to every client.
func TestProtocolMapperRepository_RealmWideMappersAreApplied(t *testing.T) {
	repo, db, cleanup := setupProtocolMapperTest(t)
	defer cleanup()
	ctx := context.Background()

	require.NoError(t, repo.CreateProtocolMapper(ctx, &domain.ProtocolMapper{
		Name: "client-a-claim", Protocol: "openid-connect",
		ProtocolMapper: "oidc-hardcoded-claim-mapper", ClientID: "client-a",
	}))
	require.NoError(t, repo.CreateProtocolMapper(ctx, &domain.ProtocolMapper{
		Name: "realm-claim", Protocol: "openid-connect",
		ProtocolMapper: "oidc-hardcoded-claim-mapper",
	}))
	// GraphQL nulls are stored as an explicit null, which must also be
	// treated as realm-wide.
	_, err := db.Collection(mongodb.ProtocolMappersCollection).InsertOne(ctx, bson.M{
		"_id": "explicit-null", "name": "null-claim", "protocol": "openid-connect",
		"protocol_mapper": "oidc-hardcoded-claim-mapper", "client_id": nil,
	})
	require.NoError(t, err)

	forClientA, err := repo.ListClientProtocolMappers(ctx, "client-a")
	require.NoError(t, err)
	require.Len(t, forClientA, 3)

	forClientB, err := repo.ListClientProtocolMappers(ctx, "client-b")
	require.NoError(t, err)
	require.Len(t, forClientB, 2, "realm-wide mappers apply to every client")

	realm, err := repo.ListRealmProtocolMappers(ctx)
	require.NoError(t, err)
	require.Len(t, realm, 2)
	for _, m := range realm {
		require.Empty(t, m.ClientID)
	}
}
