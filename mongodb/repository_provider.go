package mongodb

import (
	"context"
	"errors" // Standard Go errors package
	"fmt"

	"github.com/pilab-dev/shadow-sso/cache"
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
	userRepo           domain.UserRepository
	sessionRepo        domain.SessionRepository
	fedIDRepo          domain.UserFederatedIdentityRepository
	userAttrRepo       domain.UserAttributeRepository
	userAttrMapperRepo domain.UserAttributeMapperRepository
	tokenRepo          domain.TokenRepository
	authCodeRepo       domain.AuthorizationCodeRepository
	pkceRepo           domain.PkceRepository // See PkceRepository method for discussion
	deviceAuthRepo     domain.DeviceAuthorizationRepository
	pubKeyRepo         domain.PublicKeyRepository
	saRepo             domain.ServiceAccountRepository
	idpRepo            domain.IdPRepository
	configRepo         domain.ConfigurationRepository
	clientRepo         *ClientRepository
	flowStore          domain.FlowStore
	userSessionStore   domain.UserSessionStore
	tokenCache         cache.TokenStore
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

// Ping checks the MongoDB connection by pinging the server.
func (p *MongoRepositoryProvider) Ping(ctx context.Context) error {
	if p.clientInst == nil {
		return errors.New("MongoDB client not initialized")
	}
	return p.clientInst.Ping(ctx, nil)
}

// UserRepository returns a MongoDB-backed UserRepository.
func (p *MongoRepositoryProvider) UserRepository(ctx context.Context) domain.UserRepository {
	if p.userRepo == nil && p.db != nil {
		repo, err := NewUserRepository(ctx, p.db)
		if err == nil {
			p.userRepo = repo
		}
	}
	return p.userRepo
}

// SessionRepository returns a MongoDB-backed SessionRepository.
func (p *MongoRepositoryProvider) SessionRepository(ctx context.Context) domain.SessionRepository {
	if p.sessionRepo == nil && p.db != nil {
		repo, err := NewSessionRepositoryMongo(ctx, p.db)
		if err == nil {
			p.sessionRepo = repo
		}
	}
	return p.sessionRepo
}

// UserFederatedIdentityRepository returns a MongoDB-backed UserFederatedIdentityRepository.
func (p *MongoRepositoryProvider) UserFederatedIdentityRepository(ctx context.Context) domain.UserFederatedIdentityRepository {
	if p.fedIDRepo == nil && p.db != nil {
		idpRepo := p.IdPRepository(ctx)
		repo, err := NewUserFederatedIdentityRepositoryMongo(ctx, p.db, idpRepo)
		if err == nil {
			p.fedIDRepo = repo
		}
	}
	return p.fedIDRepo
}

// UserAttributeRepository returns a MongoDB-backed UserAttributeRepository.
func (p *MongoRepositoryProvider) UserAttributeRepository(ctx context.Context) domain.UserAttributeRepository {
	if p.userAttrRepo == nil && p.db != nil {
		repo, err := NewUserAttributeRepository(ctx, p.db)
		if err == nil {
			p.userAttrRepo = repo
		}
	}
	return p.userAttrRepo
}

// UserAttributeMapperRepository returns a MongoDB-backed UserAttributeMapperRepository.
func (p *MongoRepositoryProvider) UserAttributeMapperRepository(ctx context.Context) domain.UserAttributeMapperRepository {
	if p.userAttrMapperRepo == nil && p.db != nil {
		repo, err := NewUserAttributeMapperRepository(ctx, p.db)
		if err == nil {
			p.userAttrMapperRepo = repo
		}
	}
	return p.userAttrMapperRepo
}

// TokenRepository returns a MongoDB-backed TokenRepository.
func (p *MongoRepositoryProvider) TokenRepository(ctx context.Context) domain.TokenRepository {
	if p.tokenRepo == nil && p.db != nil {
		p.tokenRepo = NewTokenRepository(p.db)
	}
	return p.tokenRepo
}

// AuthorizationCodeRepository returns a MongoDB-backed AuthorizationCodeRepository.
func (p *MongoRepositoryProvider) AuthorizationCodeRepository(ctx context.Context) domain.AuthorizationCodeRepository {
	if p.authCodeRepo == nil && p.db != nil {
		p.authCodeRepo = NewAuthCodeRepository(p.db)
	}
	return p.authCodeRepo
}

func (p *MongoRepositoryProvider) PkceRepository(ctx context.Context) domain.PkceRepository {
	if p.pkceRepo == nil && p.db != nil {
		p.pkceRepo = NewPkceRepository(p.db)
	}
	return p.pkceRepo
}

func (p *MongoRepositoryProvider) FlowStore(ctx context.Context) domain.FlowStore {
	if p.flowStore == nil && p.db != nil {
		p.flowStore = NewFlowStore(p.db)
	}
	return p.flowStore
}

func (p *MongoRepositoryProvider) UserSessionStore(ctx context.Context) domain.UserSessionStore {
	if p.userSessionStore == nil && p.db != nil {
		p.userSessionStore = NewUserSessionStore(p.db)
	}
	return p.userSessionStore
}

func (p *MongoRepositoryProvider) TokenStore(ctx context.Context) cache.TokenStore {
	if p.tokenCache == nil && p.db != nil {
		p.tokenCache = NewTokenCache(p.db)
	}
	return p.tokenCache
}

// DeviceAuthorizationRepository returns a MongoDB-backed DeviceAuthorizationRepository.
func (p *MongoRepositoryProvider) DeviceAuthorizationRepository(ctx context.Context) domain.DeviceAuthorizationRepository {
	if p.deviceAuthRepo == nil && p.db != nil {
		p.deviceAuthRepo = NewDeviceAuthRepository(p.db)
	}
	return p.deviceAuthRepo
}

// PublicKeyRepository returns a MongoDB-backed PublicKeyRepository.
func (p *MongoRepositoryProvider) PublicKeyRepository(ctx context.Context) domain.PublicKeyRepository {
	if p.pubKeyRepo == nil && p.db != nil {
		repo, err := NewPublicKeyRepositoryMongo(p.db)
		if err == nil {
			p.pubKeyRepo = repo
		}
	}
	return p.pubKeyRepo
}

// ServiceAccountRepository returns a MongoDB-backed ServiceAccountRepository.
func (p *MongoRepositoryProvider) ServiceAccountRepository(ctx context.Context) domain.ServiceAccountRepository {
	if p.saRepo == nil && p.db != nil {
		repo, err := NewServiceAccountRepositoryMongo(p.db)
		if err == nil {
			p.saRepo = repo
		}
	}
	return p.saRepo
}

// IdPRepository returns a MongoDB-backed IdPRepository.
func (p *MongoRepositoryProvider) IdPRepository(ctx context.Context) domain.IdPRepository {
	if p.idpRepo == nil && p.db != nil {
		repo, err := NewIdPRepositoryMongo(ctx, p.db)
		if err == nil {
			p.idpRepo = repo
		}
	}
	return p.idpRepo
}

func (p *MongoRepositoryProvider) ClientRepository(ctx context.Context) domain.ClientRepository {
	if p.clientRepo == nil && p.db != nil {
		p.clientRepo = NewClientRepository(p.db)
	}
	return p.clientRepo
}

// Database returns the underlying MongoDB database instance.
// This is used for direct database access by subsystems that need it
// (e.g., GraphQL resolver creation).
func (p *MongoRepositoryProvider) Database() *mongo.Database {
	return p.db
}

// ConfigurationRepository returns a MongoDB-backed ConfigurationRepository.
func (p *MongoRepositoryProvider) ConfigurationRepository(ctx context.Context) domain.ConfigurationRepository {
	if p.configRepo == nil {
		p.configRepo = NewConfigurationRepository(p.db)
	}
	return p.configRepo
}
