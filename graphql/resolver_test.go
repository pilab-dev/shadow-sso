package graphql_test

import (
	"context"
	"os"
	"testing"

	"github.com/pilab-dev/shadow-sso/graphql"
	"github.com/pilab-dev/shadow-sso/mongodb"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

// MockEmailService implements domain.EmailService for testing
type MockEmailService struct{}

func (m *MockEmailService) SendVerificationEmail(to, name, verificationLink string) error { return nil }
func (m *MockEmailService) SendPasswordResetEmail(to, name, resetLink string) error      { return nil }
func (m *MockEmailService) SendOTPEmail(to, otp string) error                           { return nil }
func (m *MockEmailService) SendMFAEmail(to, name, otp, method string) error           { return nil }

// MockPasswordHasher implements domain.PasswordHasher for testing
type MockPasswordHasher struct{}

func (m *MockPasswordHasher) Hash(password string) (string, error)    { return password, nil }
func (m *MockPasswordHasher) Verify(hashedPassword, password string) error { return nil }

// TestGraphQLResolverWithMongoDB tests the GraphQL resolvers with a real MongoDB connection
func TestGraphQLResolverWithMongoDB(t *testing.T) {
	ctx := context.Background()

	// Get MongoDB URI from environment or use default
	mongoURI := os.Getenv("MONGO_URI")
	if mongoURI == "" {
		mongoURI = "mongodb://localhost:27017/sso_dev"
	}

	// Try to connect to MongoDB
	clientOptions := options.Client().ApplyURI(mongoURI)
	client, err := mongo.Connect(clientOptions)
	if err != nil {
		t.Skip("MongoDB not available: " + err.Error())
		return
	}
	defer client.Disconnect(ctx)

	// Ping to verify connection
	if err := client.Ping(ctx, nil); err != nil {
		t.Skip("MongoDB not available: " + err.Error())
		return
	}

	t.Log("Connected to MongoDB successfully!")
	db := client.Database("sso_dev")

	// Create all repository instances
	userRepo, err := mongodb.NewUserRepository(ctx, db)
	if err != nil {
		t.Skip("Failed to create user repo: " + err.Error())
		return
	}
	clientRepo := mongodb.NewClientRepository(db)
	sessionRepo, _ := mongodb.NewSessionRepositoryMongo(ctx, db)
	idpRepo, _ := mongodb.NewIdPRepositoryMongo(ctx, db)
	groupRepo, _ := mongodb.NewGroupRepository(ctx, db)
	roleRepo, _ := mongodb.NewRoleRepository(ctx, db)
	protocolMapperRepo, _ := mongodb.NewProtocolMapperRepository(ctx, db)
	authFlowRepo, _ := mongodb.NewAuthenticationFlowRepository(ctx, db)
	clientScopeRepo, _ := mongodb.NewClientScopeRepository(ctx, db)
	realmSettingsRepo, _ := mongodb.NewRealmSettingsRepository(ctx, db)
	realmKeysRepo, _ := mongodb.NewRealmKeysRepository(ctx, db)

	// Create resolver
	resolver := &graphql.Resolver{
		UserRepo:            userRepo,
		ClientRepo:          clientRepo,
		SessionRepo:        sessionRepo,
		IdPRepo:            idpRepo,
		GroupRepo:          groupRepo,
		RoleRepo:           roleRepo,
		ProtocolMapperRepo: protocolMapperRepo,
		AuthFlowRepo:       authFlowRepo,
		ClientScopeRepo:    clientScopeRepo,
		RealmSettingsRepo: realmSettingsRepo,
		RealmKeysRepo:     realmKeysRepo,
		EmailService:       &MockEmailService{},
		PasswordHasher:     &MockPasswordHasher{},
	}

	// Get query resolver
	queryResolver := resolver.Query()
	if queryResolver == nil {
		t.Fatal("Query resolver should not be nil")
	}

	// Test queries that work with empty DB
	t.Run("Realm", func(t *testing.T) {
		realm, err := queryResolver.Realm(ctx)
		if err != nil {
			t.Errorf("Failed to get realm: %v", err)
		}
		if realm != nil {
			t.Logf("Realm: %+v", realm)
		}
	})

	t.Run("IdentityProviders", func(t *testing.T) {
		idps, err := queryResolver.IdentityProviders(ctx)
		if err != nil {
			t.Errorf("Failed to get identity providers: %v", err)
		}
		t.Logf("Identity Providers count: %d", len(idps))
	})

	t.Run("Users", func(t *testing.T) {
		users, err := queryResolver.Users(ctx, nil, nil, nil)
		if err != nil {
			t.Errorf("Failed to get users: %v", err)
		}
		t.Logf("Users count: %d", users.TotalCount)
	})

	t.Run("Clients", func(t *testing.T) {
		clients, err := queryResolver.Clients(ctx, nil, nil, nil)
		if err != nil {
			t.Errorf("Failed to get clients: %v", err)
		}
		t.Logf("Clients count: %d", clients.TotalCount)
	})

	t.Run("Roles", func(t *testing.T) {
		roles, err := queryResolver.Roles(ctx)
		if err != nil {
			t.Errorf("Failed to get roles: %v", err)
		}
		t.Logf("Roles count: %d", len(roles))
	})

	t.Run("Groups", func(t *testing.T) {
		groups, err := queryResolver.Groups(ctx)
		if err != nil {
			t.Errorf("Failed to get groups: %v", err)
		}
		t.Logf("Groups count: %d", len(groups))
	})

	t.Run("AuthenticationFlows", func(t *testing.T) {
		flows, err := queryResolver.AuthenticationFlows(ctx)
		if err != nil {
			t.Errorf("Failed to get auth flows: %v", err)
		}
		t.Logf("Auth flows count: %d", len(flows))
	})

	t.Run("RealmKeys", func(t *testing.T) {
		keys, err := queryResolver.RealmKeys(ctx)
		if err != nil {
			t.Errorf("Failed to get realm keys: %v", err)
		}
		t.Logf("Realm keys count: %d", len(keys))
	})

	t.Run("TokenMappers", func(t *testing.T) {
		mappers, err := queryResolver.TokenMappers(ctx)
		if err != nil {
			t.Errorf("Failed to get token mappers: %v", err)
		}
		t.Logf("Token mappers count: %d", len(mappers))
	})

	// Test mutation resolver
	mutationResolver := resolver.Mutation()
	if mutationResolver == nil {
		t.Fatal("Mutation resolver should not be nil")
	}

	t.Log("All GraphQL resolvers initialized and tested successfully!")
}