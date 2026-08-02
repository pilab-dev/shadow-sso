package mongodb

import (
	"context"
	"errors" // Standard Go errors package
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/pilab-dev/shadow-sso/cache"
	"github.com/pilab-dev/shadow-sso/domain"
	"github.com/rs/zerolog/log"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
	"go.opentelemetry.io/contrib/instrumentation/go.mongodb.org/mongo-driver/v2/mongo/otelmongo"
)

// mongoConnectTimeout bounds each connect+ping attempt in
// NewMongoRepositoryProvider so an unreachable MongoDB doesn't hang the
// caller (e.g. server startup, or a test harness) indefinitely.
const mongoConnectTimeout = 10 * time.Second

// mongoConnectBackoff paces retries when SSSO_MONGO_CONNECT_RETRIES > 0.
var mongoConnectBackoff = []time.Duration{1 * time.Second, 2 * time.Second, 4 * time.Second}

// mongoConnectRetriesFromEnv returns how many extra connect attempts to make
// after the first failure. Defaults to 0 (fail fast on the first attempt) —
// tests and local dev want an unreachable MongoDB to fail immediately, not
// hang behind retries. Production deployments that want to tolerate a brief
// MongoDB blip during a rolling restart can opt in via SSSO_MONGO_CONNECT_RETRIES.
func mongoConnectRetriesFromEnv() int {
	v := os.Getenv("SSSO_MONGO_CONNECT_RETRIES")
	if v == "" {
		return 0
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 0 {
		log.Warn().Str("value", v).Msg("Invalid SSSO_MONGO_CONNECT_RETRIES, defaulting to 0")
		return 0
	}
	return n
}

// mongoPoolSizeFromEnv reads an optional pool size knob from the environment.
// Returns 0 (meaning "use the driver default") if unset or invalid.
func mongoPoolSizeFromEnv(envVar string) uint64 {
	v := os.Getenv(envVar)
	if v == "" {
		return 0
	}
	n, err := strconv.ParseUint(v, 10, 64)
	if err != nil {
		log.Warn().Str("env", envVar).Str("value", v).Msg("Invalid MongoDB pool size, ignoring")
		return 0
	}
	return n
}

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
	groupRepo          domain.GroupRepository
	roleRepo           domain.RoleRepository
	realmKeysRepo      domain.RealmKeysRepository
	protocolMapperRepo domain.ProtocolMapperRepository
	authFlowRepo       domain.AuthenticationFlowRepository
	clientScopeRepo    domain.ClientScopeRepository
	realmSettingsRepo  domain.RealmSettingsRepository
}

// NewMongoRepositoryProvider creates a new instance of MongoRepositoryProvider.
// It requires a MongoDB URI and the database name.
func NewMongoRepositoryProvider(mongoURI, dbName string) (*MongoRepositoryProvider, error) {
	if mongoURI == "" || dbName == "" {
		return nil, errors.New("mongoURI and dbName must be provided")
	}

	log.Info().Str("uri", maskMongoURI(mongoURI)).Str("db", dbName).Msg("Connecting to MongoDB")

	clientOptions := options.Client().ApplyURI(mongoURI).
		SetConnectTimeout(mongoConnectTimeout).
		SetMonitor(otelmongo.NewMonitor())
	if maxPoolSize := mongoPoolSizeFromEnv("SSSO_MONGO_MAX_POOL_SIZE"); maxPoolSize > 0 {
		clientOptions.SetMaxPoolSize(maxPoolSize)
	}
	if minPoolSize := mongoPoolSizeFromEnv("SSSO_MONGO_MIN_POOL_SIZE"); minPoolSize > 0 {
		clientOptions.SetMinPoolSize(minPoolSize)
	}

	// Connect + ping, optionally retrying a few times (SSSO_MONGO_CONNECT_RETRIES)
	// so a transient outage at boot doesn't immediately crash the caller.
	// Each attempt is bounded so a genuinely unreachable MongoDB still fails
	// fast rather than hanging (retries default to 0, see mongoConnectRetriesFromEnv).
	retries := mongoConnectRetriesFromEnv()
	var clientInst *mongo.Client
	var err error
	for attempt := 0; attempt <= retries; attempt++ {
		if attempt > 0 {
			backoff := mongoConnectBackoff[min(attempt-1, len(mongoConnectBackoff)-1)]
			log.Warn().Err(err).Int("attempt", attempt).Dur("backoff", backoff).Msg("Retrying MongoDB connection")
			time.Sleep(backoff)
		}

		clientInst, err = mongo.Connect(clientOptions)
		if err != nil {
			continue
		}

		pingCtx, cancel := context.WithTimeout(context.Background(), mongoConnectTimeout)
		err = clientInst.Ping(pingCtx, nil)
		cancel()
		if err == nil {
			break
		}
		// Attempt to disconnect if ping fails to clean up resources before retrying.
		_ = clientInst.Disconnect(context.Background())
	}
	if err != nil {
		return nil, fmt.Errorf("failed to connect to MongoDB after %d attempts: %w", retries+1, err)
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
		p.tokenRepo = NewTokenRepository(ctx, p.db)
	}
	return p.tokenRepo
}

// AuthorizationCodeRepository returns a MongoDB-backed AuthorizationCodeRepository.
func (p *MongoRepositoryProvider) AuthorizationCodeRepository(ctx context.Context) domain.AuthorizationCodeRepository {
	if p.authCodeRepo == nil && p.db != nil {
		p.authCodeRepo = NewAuthCodeRepository(ctx, p.db)
	}
	return p.authCodeRepo
}

func (p *MongoRepositoryProvider) PkceRepository(ctx context.Context) domain.PkceRepository {
	if p.pkceRepo == nil && p.db != nil {
		p.pkceRepo = NewPkceRepository(ctx, p.db)
	}
	return p.pkceRepo
}

func (p *MongoRepositoryProvider) FlowStore(ctx context.Context) domain.FlowStore {
	if p.flowStore == nil && p.db != nil {
		p.flowStore = NewFlowStore(ctx, p.db)
	}
	return p.flowStore
}

func (p *MongoRepositoryProvider) UserSessionStore(ctx context.Context) domain.UserSessionStore {
	if p.userSessionStore == nil && p.db != nil {
		p.userSessionStore = NewUserSessionStore(ctx, p.db)
	}
	return p.userSessionStore
}

func (p *MongoRepositoryProvider) TokenStore(ctx context.Context) cache.TokenStore {
	if p.tokenCache == nil && p.db != nil {
		p.tokenCache = NewTokenCache(ctx, p.db)
	}
	return p.tokenCache
}

// DeviceAuthorizationRepository returns a MongoDB-backed DeviceAuthorizationRepository.
func (p *MongoRepositoryProvider) DeviceAuthorizationRepository(ctx context.Context) domain.DeviceAuthorizationRepository {
	if p.deviceAuthRepo == nil && p.db != nil {
		p.deviceAuthRepo = NewDeviceAuthRepository(ctx, p.db)
	}
	return p.deviceAuthRepo
}

// PublicKeyRepository returns a MongoDB-backed PublicKeyRepository.
func (p *MongoRepositoryProvider) PublicKeyRepository(ctx context.Context) domain.PublicKeyRepository {
	if p.pubKeyRepo == nil && p.db != nil {
		repo, err := NewPublicKeyRepositoryMongo(ctx, p.db)
		if err == nil {
			p.pubKeyRepo = repo
		}
	}
	return p.pubKeyRepo
}

// ServiceAccountRepository returns a MongoDB-backed ServiceAccountRepository.
func (p *MongoRepositoryProvider) ServiceAccountRepository(ctx context.Context) domain.ServiceAccountRepository {
	if p.saRepo == nil && p.db != nil {
		repo, err := NewServiceAccountRepositoryMongo(ctx, p.db)
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
		p.clientRepo = NewClientRepository(ctx, p.db)
	}
	return p.clientRepo
}

// Database returns the underlying MongoDB database instance.
// This is used for direct database access by subsystems that need it
// (e.g., GraphQL resolver creation).
func (p *MongoRepositoryProvider) Database() *mongo.Database {
	return p.db
}

// GroupRepository returns a MongoDB-backed GroupRepository.
func (p *MongoRepositoryProvider) GroupRepository(ctx context.Context) domain.GroupRepository {
	if p.groupRepo == nil && p.db != nil {
		repo, err := NewGroupRepository(ctx, p.db)
		if err == nil {
			p.groupRepo = repo
		}
	}
	return p.groupRepo
}

// RoleRepository returns a MongoDB-backed RoleRepository.
func (p *MongoRepositoryProvider) RoleRepository(ctx context.Context) domain.RoleRepository {
	if p.roleRepo == nil && p.db != nil {
		repo, err := NewRoleRepository(ctx, p.db)
		if err == nil {
			p.roleRepo = repo
		}
	}
	return p.roleRepo
}

// RealmKeysRepository returns a MongoDB-backed RealmKeysRepository.
func (p *MongoRepositoryProvider) RealmKeysRepository(ctx context.Context) domain.RealmKeysRepository {
	if p.realmKeysRepo == nil && p.db != nil {
		repo, err := NewRealmKeysRepository(ctx, p.db)
		if err == nil {
			p.realmKeysRepo = repo
		}
	}
	return p.realmKeysRepo
}

// ConfigurationRepository returns a MongoDB-backed ConfigurationRepository.
func (p *MongoRepositoryProvider) ConfigurationRepository(ctx context.Context) domain.ConfigurationRepository {
	if p.configRepo == nil {
		p.configRepo = NewConfigurationRepository(ctx, p.db)
	}
	return p.configRepo
}

// ProtocolMapperRepository returns a MongoDB-backed ProtocolMapperRepository.
func (p *MongoRepositoryProvider) ProtocolMapperRepository(ctx context.Context) domain.ProtocolMapperRepository {
	if p.protocolMapperRepo == nil && p.db != nil {
		repo, err := NewProtocolMapperRepository(ctx, p.db)
		if err == nil {
			p.protocolMapperRepo = repo
		}
	}
	return p.protocolMapperRepo
}

// AuthenticationFlowRepository returns a MongoDB-backed AuthenticationFlowRepository.
func (p *MongoRepositoryProvider) AuthenticationFlowRepository(ctx context.Context) domain.AuthenticationFlowRepository {
	if p.authFlowRepo == nil && p.db != nil {
		repo, err := NewAuthenticationFlowRepository(ctx, p.db)
		if err == nil {
			p.authFlowRepo = repo
		}
	}
	return p.authFlowRepo
}

// ClientScopeRepository returns a MongoDB-backed ClientScopeRepository.
func (p *MongoRepositoryProvider) ClientScopeRepository(ctx context.Context) domain.ClientScopeRepository {
	if p.clientScopeRepo == nil && p.db != nil {
		repo, err := NewClientScopeRepository(ctx, p.db)
		if err == nil {
			p.clientScopeRepo = repo
		}
	}
	return p.clientScopeRepo
}

// RealmSettingsRepository returns a MongoDB-backed RealmSettingsRepository.
func (p *MongoRepositoryProvider) RealmSettingsRepository(ctx context.Context) domain.RealmSettingsRepository {
	if p.realmSettingsRepo == nil && p.db != nil {
		repo, err := NewRealmSettingsRepository(ctx, p.db)
		if err == nil {
			p.realmSettingsRepo = repo
		}
	}
	return p.realmSettingsRepo
}
