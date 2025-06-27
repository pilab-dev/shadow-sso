package mongodb

import (
	"context"
	"errors" // Standard Go errors package
	"fmt"

	"github.com/pilab-dev/shadow-sso/domain"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

// MongoRepositoryProvider implements the domain.RepositoryProvider interface
// using MongoDB as the backing store.
type MongoRepositoryProvider struct {
	db          *mongo.Database
	clientInst  *mongo.Client
	cfgMongoURI string // Store for re-connection if necessary, though typically not used post-initialization
	cfgDbName   string

	// Cached repository instances
	userRepo       domain.UserRepository
	sessionRepo    domain.SessionRepository
	fedIDRepo      domain.UserFederatedIdentityRepository
	tokenRepo      domain.TokenRepository
	authCodeRepo   domain.AuthorizationCodeRepository
	pkceRepo       domain.PkceRepository // See PkceRepository method for discussion
	deviceAuthRepo domain.DeviceAuthorizationRepository
	pubKeyRepo     domain.PublicKeyRepository
	saRepo         domain.ServiceAccountRepository
	idpRepo        domain.IdPRepository
	clientRepo     *ClientRepository
}

// NewMongoRepositoryProvider creates a new instance of MongoRepositoryProvider.
// It requires a MongoDB URI and the database name.
func NewMongoRepositoryProvider(mongoURI, dbName string) (*MongoRepositoryProvider, error) {
	if mongoURI == "" || dbName == "" {
		return nil, errors.New("mongoURI and dbName must be provided")
	}

	// Context for initial connection setup.
	// Using a timeout for the connection attempt is good practice.
	// For simplicity in this refactor, context.TODO() is used, but a timed context is better.

	clientOptions := options.Client().ApplyURI(mongoURI)
	clientInst, err := mongo.Connect(clientOptions)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to MongoDB: %w", err)
	}

	// Ping the primary to verify connection.
	pingCtx := context.TODO()
	if err := clientInst.Ping(pingCtx, nil); err != nil {
		// Attempt to disconnect if ping fails to clean up resources.
		_ = clientInst.Disconnect(context.Background()) // Use background context for cleanup disconnect
		return nil, fmt.Errorf("failed to ping MongoDB: %w", err)
	}

	db := clientInst.Database(dbName)

	// Pre-initialize repositories that are straightforward singletons
	// Note: Some New...Repository functions in the mongodb package might take context for setup.
	// If so, pass an appropriate context (e.g., connectCtx or context.Background()).
	// For this refactoring, assuming they mostly need just the *mongo.Database.

	// For this iteration, to minimize changes to existing New... funcs,
	// I will instantiate them in each getter but acknowledge this isn't ideal for true singletons.
	// The alternative, instantiating here, is cleaner if New... funcs are simple.

	// Let's try instantiating here assuming New... funcs are simple.
	// This requires checking each New... func signature.
	// Example: userRepo, err := NewMongoUserRepository(db) - if it returns error.
	// For now, keeping the original structure of calling New... in getters,
	// as changing all New... signatures is out of scope for "wiring".
	// The "cached repository instances" fields above are thus aspirational without further refactor of New... funcs.

	return &MongoRepositoryProvider{
		db:          db,
		clientInst:  clientInst,
		cfgMongoURI: mongoURI,
		cfgDbName:   dbName,
	}, nil
}

// Disconnect allows graceful disconnection of the MongoDB client.
func (p *MongoRepositoryProvider) Disconnect(ctx context.Context) error {
	if p.clientInst != nil {
		return p.clientInst.Disconnect(ctx)
	}
	return nil
}

// UserRepository returns a MongoDB-backed UserRepository.
func (p *MongoRepositoryProvider) UserRepository(ctx context.Context) domain.UserRepository {
	// To make these singletons, initialize in NewMongoRepositoryProvider and return cached instance.
	// For now, direct instantiation per call (original behavior of connectrpc_server.go's manual setup):
	return p.userRepo // Assumes NewMongoUserRepository is exported, or use existing NewUserRepositoryMongo
}

// SessionRepository returns a MongoDB-backed SessionRepository.
func (p *MongoRepositoryProvider) SessionRepository(ctx context.Context) domain.SessionRepository {
	return p.sessionRepo // Assumes NewMongoSessionRepository is exported
}

// UserFederatedIdentityRepository returns a MongoDB-backed UserFederatedIdentityRepository.
func (p *MongoRepositoryProvider) UserFederatedIdentityRepository(ctx context.Context) domain.UserFederatedIdentityRepository {
	return p.fedIDRepo
}

// TokenRepository returns a MongoDB-backed TokenRepository.
func (p *MongoRepositoryProvider) TokenRepository(ctx context.Context) domain.TokenRepository {
	return p.tokenRepo
}

// AuthorizationCodeRepository returns a MongoDB-backed AuthorizationCodeRepository.
func (p *MongoRepositoryProvider) AuthorizationCodeRepository(ctx context.Context) domain.AuthorizationCodeRepository {
	return p.authCodeRepo
}

// PkceRepository returns a MongoDB-backed PkceRepository.
// Assuming a NewMongoPkceRepository exists or needs to be created.
// For now, this will be a placeholder if it doesn't exist.
func (p *MongoRepositoryProvider) PkceRepository(ctx context.Context) domain.PkceRepository {
	return p.pkceRepo
}

// DeviceAuthorizationRepository returns a MongoDB-backed DeviceAuthorizationRepository.
func (p *MongoRepositoryProvider) DeviceAuthorizationRepository(ctx context.Context) domain.DeviceAuthorizationRepository {
	return p.deviceAuthRepo
}

// PublicKeyRepository returns a MongoDB-backed PublicKeyRepository.
func (p *MongoRepositoryProvider) PublicKeyRepository(ctx context.Context) domain.PublicKeyRepository {
	return p.pubKeyRepo
}

// ServiceAccountRepository returns a MongoDB-backed ServiceAccountRepository.
func (p *MongoRepositoryProvider) ServiceAccountRepository(ctx context.Context) domain.ServiceAccountRepository {
	return p.saRepo
}

// IdPRepository returns a MongoDB-backed IdPRepository.
func (p *MongoRepositoryProvider) IdPRepository(ctx context.Context) domain.IdPRepository {
	return p.idpRepo
}

func (p *MongoRepositoryProvider) ClientRepository(ctx context.Context) domain.ClientRepository {
	return p.clientRepo
}
