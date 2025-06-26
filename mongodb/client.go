package mongodb

import (
	"context"
	"errors" // Added for errors.New
	"sync"
	"time"

	"github.com/rs/zerolog/log"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
	"go.mongodb.org/mongo-driver/v2/mongo/readpref"
	"go.opentelemetry.io/contrib/instrumentation/go.mongodb.org/mongo-driver/v2/mongo/otelmongo"
)

const (
	UsersCollection           = "oauth_users"           // For users
	ClientsCollection         = "oauth_clients"         // For OAuth clients
	CodesCollection           = "oauth_auth_codes"      // For authorization codes
	TokensCollection          = "oauth_tokens"          // For user OAuth tokens
	ChallengesCollection      = "oauth_pkce_challenges" // For PKCE challenges
	UserSessionsCollection    = "oauth_user_sessions"   // For user login sessions (if stored in mongo)
	ServiceAccountsCollection = "service_accounts"      // For service accounts
	PublicKeysCollection      = "public_keys"           // For service account public keys
	IdPsCollection            = "identity_providers"    // For identity providers
	DeviceAuthCollectionName  = "device_authorizations" // For device authorization codes (RFC 8628)
)

var (
	clientInstance *mongo.Client
	clientOnce     sync.Once
	dbInstance     *mongo.Database
	dbOnce         sync.Once
)

// InitMongoDB initializes the MongoDB client and database instances.
// It should be called once at application startup.
// URI and dbName can be overridden by environment variables or config.
func InitMongoDB(ctx context.Context, uri, dbName string) error {
	var err error
	clientOnce.Do(func() {
		log.Info().Msgf("Initializing MongoDB client with URI: %s", uri)
		// Instrument the MongoDB client - currently incompatible with mongo-driver/v2
		// clientOptions := options.Client().ApplyURI(uri).SetMonitor(otelmongo.NewMonitor())
		clientOptions := options.Client().ApplyURI(uri)
		clientOptions.SetConnectTimeout(10 * time.Second)
		// Add other client options as needed (e.g., auth, replica set)
		clientOptions.SetMonitor(
			otelmongo.NewMonitor(),
		)

		client, clientErr := mongo.Connect(clientOptions)
		if clientErr != nil {
			err = clientErr // Capture error for outer scope
			log.Fatal().Err(clientErr).Msg("Failed to connect to MongoDB")
			return
		}

		// Ping the primary to verify connection.
		if pingErr := client.Ping(ctx, readpref.Primary()); pingErr != nil {
			err = pingErr // Capture error
			log.Fatal().Err(pingErr).Msg("Failed to ping MongoDB primary")
			// client.Disconnect(ctx) // Should we disconnect if ping fails? Usually Connect handles this.
			return
		}
		clientInstance = client
		log.Info().Msg("MongoDB client initialized successfully.")
	})
	if err != nil {
		return err // Return error from clientOnce.Do if any
	}
	if clientInstance == nil && err == nil { // Should not happen if clientOnce.Do completed without error
		return errors.New("mongodb client not initialized after Do, but no error reported")
	}

	dbOnce.Do(func() {
		if clientInstance == nil {
			log.Error().Msg("MongoDB client is nil, cannot initialize database instance.")
			err = errors.New("cannot initialize database without a connected client")
			return
		}
		log.Info().Msgf("Using MongoDB database: %s", dbName)
		dbInstance = clientInstance.Database(dbName)
	})

	if err != nil {
		return err // Return error from dbOnce.Do
	}

	if dbInstance == nil && err == nil {
		return errors.New("mongodb database instance not initialized after Do, but no error reported")
	}

	return nil // Both initializations successful or already done
}

// GetDB returns the MongoDB database instance.
// It panics if InitMongoDB has not been called successfully.
func GetDB() *mongo.Database {
	if dbInstance == nil {
		log.Fatal().Msg("MongoDB database instance is not initialized. Call InitMongoDB first.")
		// Or return an error: return nil, errors.New("MongoDB not initialized")
	}
	return dbInstance
}

// GetClient returns the MongoDB client instance.
// It panics if InitMongoDB has not been called successfully.
func GetClient() *mongo.Client {
	if clientInstance == nil {
		log.Fatal().Msg("MongoDB client instance is not initialized. Call InitMongoDB first.")
	}
	return clientInstance
}

// Ping sends a ping to the MongoDB server using the global client.
// This is useful for health checks.
func Ping(ctx context.Context) error {
	if clientInstance == nil {
		return errors.New("MongoDB client is not initialized. Call InitMongoDB first.")
	}
	// Use a short timeout for pings
	pingCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	return clientInstance.Ping(pingCtx, readpref.Primary())
}

// CloseMongoDB disconnects the MongoDB client.
// It should be called on application shutdown.
func CloseMongoDB(ctx context.Context) {
	if clientInstance != nil {
		log.Info().Msg("Closing MongoDB connection.")
		if err := clientInstance.Disconnect(ctx); err != nil {
			log.Error().Err(err).Msg("Error closing MongoDB connection")
		}
	}
}
