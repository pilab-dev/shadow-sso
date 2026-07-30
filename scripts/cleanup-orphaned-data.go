//go:build ignore

package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/joho/godotenv"
	"github.com/rs/zerolog/log"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

// Collection names (matching mongodb/client.go)
const (
	UsersCollection           = "oauth_users"
	ClientsCollection         = "oauth_clients"
	CodesCollection           = "oauth_auth_codes"
	TokensCollection          = "oauth_tokens"
	ChallengesCollection      = "oauth_pkce_challenges"
	UserSessionsCollection    = "oauth_user_sessions"
	ServiceAccountsCollection = "service_accounts"
	PublicKeysCollection      = "public_keys"
	IdPsCollection            = "identity_providers"
	DeviceAuthCollectionName  = "device_authorizations"
	UserSessionsOIDCCollection = "user_sessions_oidc"
	GroupsCollection          = "realm_groups"
)

type CleanupResult struct {
	Collection string
	Count      int64
	Action     string
}

func main() {
	// Load .env file from parent directory (project root)
	if err := godotenv.Load("../.env"); err != nil {
		log.Warn().Err(err).Msg("No .env file found in parent directory, trying current directory")
		if err := godotenv.Load(); err != nil {
			log.Warn().Err(err).Msg("No .env file found")
		}
	}

	mongoURI := os.Getenv("SSSO_MONGO_URI")
	dbName := os.Getenv("SSSO_MONGO_DB_NAME")

	if mongoURI == "" {
		log.Fatal().Msg("SSSO_MONGO_URI environment variable is required")
	}
	if dbName == "" {
		log.Fatal().Msg("SSSO_MONGO_DB_NAME environment variable is required")
	}

	log.Info().Str("uri", maskURI(mongoURI)).Str("db", dbName).Msg("Connecting to MongoDB")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	client, err := mongo.Connect(options.Client().ApplyURI(mongoURI))
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to connect to MongoDB")
	}
	defer client.Disconnect(ctx)

	if err := client.Ping(ctx, nil); err != nil {
		log.Fatal().Err(err).Msg("Failed to ping MongoDB")
	}

	db := client.Database(dbName)
	log.Info().Msg("Connected to MongoDB successfully")

	var results []CleanupResult

	// 1. Clean expired tokens
	log.Info().Msg("Cleaning expired tokens...")
	result, err := cleanupExpiredTokens(ctx, db)
	if err != nil {
		log.Error().Err(err).Msg("Failed to cleanup expired tokens")
	} else {
		results = append(results, result)
	}

	// 2. Clean tokens without valid users
	log.Info().Msg("Cleaning tokens without valid users...")
	result, err = cleanupOrphanedTokensByUser(ctx, db)
	if err != nil {
		log.Error().Err(err).Msg("Failed to cleanup orphaned tokens by user")
	} else {
		results = append(results, result)
	}

	// 3. Clean tokens without valid clients
	log.Info().Msg("Cleaning tokens without valid clients...")
	result, err = cleanupOrphanedTokensByClient(ctx, db)
	if err != nil {
		log.Error().Err(err).Msg("Failed to cleanup orphaned tokens by client")
	} else {
		results = append(results, result)
	}

	// 4. Clean sessions without valid users
	log.Info().Msg("Cleaning sessions without valid users...")
	result, err = cleanupOrphanedSessions(ctx, db)
	if err != nil {
		log.Error().Err(err).Msg("Failed to cleanup orphaned sessions")
	} else {
		results = append(results, result)
	}

	// 5. Clean OIDC sessions without valid users
	log.Info().Msg("Cleaning OIDC sessions without valid users...")
	result, err = cleanupOrphanedOIDCSessions(ctx, db)
	if err != nil {
		log.Error().Err(err).Msg("Failed to cleanup orphaned OIDC sessions")
	} else {
		results = append(results, result)
	}

	// 6. Clean authorization codes without valid users
	log.Info().Msg("Cleaning authorization codes without valid users...")
	result, err = cleanupOrphanedAuthCodesByUser(ctx, db)
	if err != nil {
		log.Error().Err(err).Msg("Failed to cleanup orphaned auth codes by user")
	} else {
		results = append(results, result)
	}

	// 7. Clean authorization codes without valid clients
	log.Info().Msg("Cleaning authorization codes without valid clients...")
	result, err = cleanupOrphanedAuthCodesByClient(ctx, db)
	if err != nil {
		log.Error().Err(err).Msg("Failed to cleanup orphaned auth codes by client")
	} else {
		results = append(results, result)
	}

	// 8. Clean expired authorization codes
	log.Info().Msg("Cleaning expired authorization codes...")
	result, err = cleanupExpiredAuthCodes(ctx, db)
	if err != nil {
		log.Error().Err(err).Msg("Failed to cleanup expired auth codes")
	} else {
		results = append(results, result)
	}

	// 9. Clean device authorizations without valid users
	log.Info().Msg("Cleaning device authorizations without valid users...")
	result, err = cleanupOrphanedDeviceAuthorizations(ctx, db)
	if err != nil {
		log.Error().Err(err).Msg("Failed to cleanup orphaned device authorizations")
	} else {
		results = append(results, result)
	}

	// 10. Clean expired device authorizations
	log.Info().Msg("Cleaning expired device authorizations...")
	result, err = cleanupExpiredDeviceAuthorizations(ctx, db)
	if err != nil {
		log.Error().Err(err).Msg("Failed to cleanup expired device authorizations")
	} else {
		results = append(results, result)
	}

	// 11. Clean public keys without valid service accounts
	log.Info().Msg("Cleaning public keys without valid service accounts...")
	result, err = cleanupOrphanedPublicKeys(ctx, db)
	if err != nil {
		log.Error().Err(err).Msg("Failed to cleanup orphaned public keys")
	} else {
		results = append(results, result)
	}

	// 12. Clean service accounts without valid clients
	log.Info().Msg("Cleaning service accounts without valid clients...")
	result, err = cleanupOrphanedServiceAccounts(ctx, db)
	if err != nil {
		log.Error().Err(err).Msg("Failed to cleanup orphaned service accounts")
	} else {
		results = append(results, result)
	}

	// Print summary
	printSummary(results)
}

func cleanupExpiredTokens(ctx context.Context, db *mongo.Database) (CleanupResult, error) {
	coll := db.Collection(TokensCollection)
	
	result, err := coll.DeleteMany(ctx, bson.M{
		"expires_at": bson.M{"$lt": time.Now().UTC()},
	})
	if err != nil {
		return CleanupResult{}, err
	}

	return CleanupResult{
		Collection: TokensCollection,
		Count:      result.DeletedCount,
		Action:     "removed expired tokens",
	}, nil
}

func cleanupOrphanedTokensByUser(ctx context.Context, db *mongo.Database) (CleanupResult, error) {
	coll := db.Collection(TokensCollection)
	usersColl := db.Collection(UsersCollection)

	// Get all user IDs
	cursor, err := usersColl.Find(ctx, bson.M{}, options.Find().SetProjection(bson.M{"_id": 1}))
	if err != nil {
		return CleanupResult{}, err
	}
	defer cursor.Close(ctx)

	var userIDs []string
	for cursor.Next(ctx) {
		var user struct {
			ID string `bson:"_id"`
		}
		if err := cursor.Decode(&user); err != nil {
			continue
		}
		userIDs = append(userIDs, user.ID)
	}

	if len(userIDs) == 0 {
		return CleanupResult{
			Collection: TokensCollection,
			Count:      0,
			Action:     "no users found, skipping orphan check",
		}, nil
	}

	// Delete tokens with user_id not in the list of valid user IDs
	result, err := coll.DeleteMany(ctx, bson.M{
		"user_id": bson.M{"$nin": userIDs},
	})
	if err != nil {
		return CleanupResult{}, err
	}

	return CleanupResult{
		Collection: TokensCollection,
		Count:      result.DeletedCount,
		Action:     "removed tokens without valid users",
	}, nil
}

func cleanupOrphanedTokensByClient(ctx context.Context, db *mongo.Database) (CleanupResult, error) {
	coll := db.Collection(TokensCollection)
	clientsColl := db.Collection(ClientsCollection)

	// Get all client IDs
	cursor, err := clientsColl.Find(ctx, bson.M{}, options.Find().SetProjection(bson.M{"client_id": 1}))
	if err != nil {
		return CleanupResult{}, err
	}
	defer cursor.Close(ctx)

	var clientIDs []string
	for cursor.Next(ctx) {
		var client struct {
			ClientID string `bson:"client_id"`
		}
		if err := cursor.Decode(&client); err != nil {
			continue
		}
		clientIDs = append(clientIDs, client.ClientID)
	}

	if len(clientIDs) == 0 {
		return CleanupResult{
			Collection: TokensCollection,
			Count:      0,
			Action:     "no clients found, skipping orphan check",
		}, nil
	}

	// Delete tokens with client_id not in the list of valid client IDs
	result, err := coll.DeleteMany(ctx, bson.M{
		"client_id": bson.M{"$nin": clientIDs},
	})
	if err != nil {
		return CleanupResult{}, err
	}

	return CleanupResult{
		Collection: TokensCollection,
		Count:      result.DeletedCount,
		Action:     "removed tokens without valid clients",
	}, nil
}

func cleanupOrphanedSessions(ctx context.Context, db *mongo.Database) (CleanupResult, error) {
	coll := db.Collection(UserSessionsCollection)
	usersColl := db.Collection(UsersCollection)

	// Get all user IDs
	cursor, err := usersColl.Find(ctx, bson.M{}, options.Find().SetProjection(bson.M{"_id": 1}))
	if err != nil {
		return CleanupResult{}, err
	}
	defer cursor.Close(ctx)

	var userIDs []string
	for cursor.Next(ctx) {
		var user struct {
			ID string `bson:"_id"`
		}
		if err := cursor.Decode(&user); err != nil {
			continue
		}
		userIDs = append(userIDs, user.ID)
	}

	if len(userIDs) == 0 {
		return CleanupResult{
			Collection: UserSessionsCollection,
			Count:      0,
			Action:     "no users found, skipping orphan check",
		}, nil
	}

	// Delete sessions with user_id not in the list of valid user IDs
	result, err := coll.DeleteMany(ctx, bson.M{
		"user_id": bson.M{"$nin": userIDs},
	})
	if err != nil {
		return CleanupResult{}, err
	}

	return CleanupResult{
		Collection: UserSessionsCollection,
		Count:      result.DeletedCount,
		Action:     "removed sessions without valid users",
	}, nil
}

func cleanupOrphanedOIDCSessions(ctx context.Context, db *mongo.Database) (CleanupResult, error) {
	coll := db.Collection(UserSessionsOIDCCollection)
	usersColl := db.Collection(UsersCollection)

	// Get all user IDs
	cursor, err := usersColl.Find(ctx, bson.M{}, options.Find().SetProjection(bson.M{"_id": 1}))
	if err != nil {
		return CleanupResult{}, err
	}
	defer cursor.Close(ctx)

	var userIDs []string
	for cursor.Next(ctx) {
		var user struct {
			ID string `bson:"_id"`
		}
		if err := cursor.Decode(&user); err != nil {
			continue
		}
		userIDs = append(userIDs, user.ID)
	}

	if len(userIDs) == 0 {
		return CleanupResult{
			Collection: UserSessionsOIDCCollection,
			Count:      0,
			Action:     "no users found, skipping orphan check",
		}, nil
	}

	// Delete OIDC sessions with user_id not in the list of valid user IDs
	result, err := coll.DeleteMany(ctx, bson.M{
		"user_id": bson.M{"$nin": userIDs},
	})
	if err != nil {
		return CleanupResult{}, err
	}

	return CleanupResult{
		Collection: UserSessionsOIDCCollection,
		Count:      result.DeletedCount,
		Action:     "removed OIDC sessions without valid users",
	}, nil
}

func cleanupOrphanedAuthCodesByUser(ctx context.Context, db *mongo.Database) (CleanupResult, error) {
	coll := db.Collection(CodesCollection)
	usersColl := db.Collection(UsersCollection)

	// Get all user IDs
	cursor, err := usersColl.Find(ctx, bson.M{}, options.Find().SetProjection(bson.M{"_id": 1}))
	if err != nil {
		return CleanupResult{}, err
	}
	defer cursor.Close(ctx)

	var userIDs []string
	for cursor.Next(ctx) {
		var user struct {
			ID string `bson:"_id"`
		}
		if err := cursor.Decode(&user); err != nil {
			continue
		}
		userIDs = append(userIDs, user.ID)
	}

	if len(userIDs) == 0 {
		return CleanupResult{
			Collection: CodesCollection,
			Count:      0,
			Action:     "no users found, skipping orphan check",
		}, nil
	}

	// Delete auth codes with user_id not in the list of valid user IDs
	result, err := coll.DeleteMany(ctx, bson.M{
		"user_id": bson.M{"$nin": userIDs},
	})
	if err != nil {
		return CleanupResult{}, err
	}

	return CleanupResult{
		Collection: CodesCollection,
		Count:      result.DeletedCount,
		Action:     "removed auth codes without valid users",
	}, nil
}

func cleanupOrphanedAuthCodesByClient(ctx context.Context, db *mongo.Database) (CleanupResult, error) {
	coll := db.Collection(CodesCollection)
	clientsColl := db.Collection(ClientsCollection)

	// Get all client IDs
	cursor, err := clientsColl.Find(ctx, bson.M{}, options.Find().SetProjection(bson.M{"client_id": 1}))
	if err != nil {
		return CleanupResult{}, err
	}
	defer cursor.Close(ctx)

	var clientIDs []string
	for cursor.Next(ctx) {
		var client struct {
			ClientID string `bson:"client_id"`
		}
		if err := cursor.Decode(&client); err != nil {
			continue
		}
		clientIDs = append(clientIDs, client.ClientID)
	}

	if len(clientIDs) == 0 {
		return CleanupResult{
			Collection: CodesCollection,
			Count:      0,
			Action:     "no clients found, skipping orphan check",
		}, nil
	}

	// Delete auth codes with client_id not in the list of valid client IDs
	result, err := coll.DeleteMany(ctx, bson.M{
		"client_id": bson.M{"$nin": clientIDs},
	})
	if err != nil {
		return CleanupResult{}, err
	}

	return CleanupResult{
		Collection: CodesCollection,
		Count:      result.DeletedCount,
		Action:     "removed auth codes without valid clients",
	}, nil
}

func cleanupExpiredAuthCodes(ctx context.Context, db *mongo.Database) (CleanupResult, error) {
	coll := db.Collection(CodesCollection)
	
	result, err := coll.DeleteMany(ctx, bson.M{
		"expires_at": bson.M{"$lt": time.Now().UTC()},
	})
	if err != nil {
		return CleanupResult{}, err
	}

	return CleanupResult{
		Collection: CodesCollection,
		Count:      result.DeletedCount,
		Action:     "removed expired auth codes",
	}, nil
}

func cleanupOrphanedDeviceAuthorizations(ctx context.Context, db *mongo.Database) (CleanupResult, error) {
	coll := db.Collection(DeviceAuthCollectionName)
	usersColl := db.Collection(UsersCollection)

	// Get all user IDs
	cursor, err := usersColl.Find(ctx, bson.M{}, options.Find().SetProjection(bson.M{"_id": 1}))
	if err != nil {
		return CleanupResult{}, err
	}
	defer cursor.Close(ctx)

	var userIDs []string
	for cursor.Next(ctx) {
		var user struct {
			ID string `bson:"_id"`
		}
		if err := cursor.Decode(&user); err != nil {
			continue
		}
		userIDs = append(userIDs, user.ID)
	}

	if len(userIDs) == 0 {
		return CleanupResult{
			Collection: DeviceAuthCollectionName,
			Count:      0,
			Action:     "no users found, skipping orphan check",
		}, nil
	}

	// Delete device authorizations with user_id not in the list of valid user IDs
	// Note: Some device authorizations may not have user_id yet (pending approval)
	result, err := coll.DeleteMany(ctx, bson.M{
		"user_id": bson.M{"$nin": userIDs, "$exists": true},
	})
	if err != nil {
		return CleanupResult{}, err
	}

	return CleanupResult{
		Collection: DeviceAuthCollectionName,
		Count:      result.DeletedCount,
		Action:     "removed device authorizations without valid users",
	}, nil
}

func cleanupExpiredDeviceAuthorizations(ctx context.Context, db *mongo.Database) (CleanupResult, error) {
	coll := db.Collection(DeviceAuthCollectionName)
	
	result, err := coll.DeleteMany(ctx, bson.M{
		"expires_at": bson.M{"$lt": time.Now().UTC()},
	})
	if err != nil {
		return CleanupResult{}, err
	}

	return CleanupResult{
		Collection: DeviceAuthCollectionName,
		Count:      result.DeletedCount,
		Action:     "removed expired device authorizations",
	}, nil
}

func cleanupOrphanedPublicKeys(ctx context.Context, db *mongo.Database) (CleanupResult, error) {
	coll := db.Collection(PublicKeysCollection)
	saColl := db.Collection(ServiceAccountsCollection)

	// Get all service account IDs
	cursor, err := saColl.Find(ctx, bson.M{}, options.Find().SetProjection(bson.M{"_id": 1}))
	if err != nil {
		return CleanupResult{}, err
	}
	defer cursor.Close(ctx)

	var saIDs []string
	for cursor.Next(ctx) {
		var sa struct {
			ID string `bson:"_id"`
		}
		if err := cursor.Decode(&sa); err != nil {
			continue
		}
		saIDs = append(saIDs, sa.ID)
	}

	if len(saIDs) == 0 {
		return CleanupResult{
			Collection: PublicKeysCollection,
			Count:      0,
			Action:     "no service accounts found, skipping orphan check",
		}, nil
	}

	// Delete public keys with service_account_id not in the list of valid service account IDs
	result, err := coll.DeleteMany(ctx, bson.M{
		"service_account_id": bson.M{"$nin": saIDs},
	})
	if err != nil {
		return CleanupResult{}, err
	}

	return CleanupResult{
		Collection: PublicKeysCollection,
		Count:      result.DeletedCount,
		Action:     "removed public keys without valid service accounts",
	}, nil
}

func cleanupOrphanedServiceAccounts(ctx context.Context, db *mongo.Database) (CleanupResult, error) {
	coll := db.Collection(ServiceAccountsCollection)
	clientsColl := db.Collection(ClientsCollection)

	// Get all client IDs
	cursor, err := clientsColl.Find(ctx, bson.M{}, options.Find().SetProjection(bson.M{"client_id": 1}))
	if err != nil {
		return CleanupResult{}, err
	}
	defer cursor.Close(ctx)

	var clientIDs []string
	for cursor.Next(ctx) {
		var client struct {
			ClientID string `bson:"client_id"`
		}
		if err := cursor.Decode(&client); err != nil {
			continue
		}
		clientIDs = append(clientIDs, client.ClientID)
	}

	if len(clientIDs) == 0 {
		return CleanupResult{
			Collection: ServiceAccountsCollection,
			Count:      0,
			Action:     "no clients found, skipping orphan check",
		}, nil
	}

	// Delete service accounts with client_id not in the list of valid client IDs
	result, err := coll.DeleteMany(ctx, bson.M{
		"client_id": bson.M{"$nin": clientIDs},
	})
	if err != nil {
		return CleanupResult{}, err
	}

	return CleanupResult{
		Collection: ServiceAccountsCollection,
		Count:      result.DeletedCount,
		Action:     "removed service accounts without valid clients",
	}, nil
}

func printSummary(results []CleanupResult) {
	fmt.Println("\n" + "========================================")
	fmt.Println("  MongoDB Cleanup Summary")
	fmt.Println("========================================")
	
	totalDeleted := int64(0)
	for _, r := range results {
		if r.Count > 0 {
			fmt.Printf("✓ %s: %d %s\n", r.Collection, r.Count, r.Action)
			totalDeleted += r.Count
		}
	}
	
	if totalDeleted == 0 {
		fmt.Println("✓ No orphaned data found. Database is clean!")
	} else {
		fmt.Printf("\n✓ Total documents removed: %d\n", totalDeleted)
	}
	fmt.Println("========================================")
}

func maskURI(uri string) string {
	// Simple masking for logging
	if len(uri) > 20 {
		return uri[:15] + "..." + uri[len(uri)-5:]
	}
	return uri
}
