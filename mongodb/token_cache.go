package mongodb

import (
	"context"
	"time"

	"github.com/pilab-dev/shadow-sso/cache"
	"github.com/rs/zerolog/log"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

// TokenCacheCollection is the MongoDB collection name for cached tokens.
const TokenCacheCollection = "token_cache"

// tokenCacheDocument is the storage document for a cached token entry.
// We define a separate document struct with bson tags because cache.TokenEntry
// uses redis tags and lacks bson tags.
type tokenCacheDocument struct {
	ID         string    `bson:"_id"`          // HashToken(tokenValue)
	TokenType  string    `bson:"token_type"`   // "access_token" or "refresh_token"
	TokenValue string    `bson:"token_value"`  // The actual token value (for LastUsedAt updates)
	ClientID   string    `bson:"client_id"`
	UserID     string    `bson:"user_id"`
	Scope      string    `bson:"scope"`
	ExpiresAt  time.Time `bson:"expires_at"`
	IsRevoked  bool      `bson:"is_revoked"`
	CreatedAt  time.Time `bson:"created_at"`
	LastUsedAt time.Time `bson:"last_used_at"`
	Roles      []string  `bson:"roles,omitempty"`
}

// MongoTokenStore implements cache.TokenStore using MongoDB as the backing store.
// It uses a TTL index on expires_at for automatic cleanup of expired tokens,
// so no background goroutines are needed.
type MongoTokenStore struct {
	collection *mongo.Collection
}

// NewTokenCache creates a new MongoTokenStore and ensures a TTL index on expires_at.
func NewTokenCache(ctx context.Context, db *mongo.Database) *MongoTokenStore {
	store := &MongoTokenStore{
		collection: db.Collection(TokenCacheCollection),
	}

	indexModels := []mongo.IndexModel{
		{
			Keys:    bson.D{{Key: "expires_at", Value: 1}},
			Options: options.Index().SetExpireAfterSeconds(0),
		},
	}
	opts := options.CreateIndexes()
	if _, err := store.collection.Indexes().CreateMany(ctx, indexModels, opts); err != nil {
		log.Warn().Err(err).Msg("Issue creating TTL index for token_cache collection (might already exist or other error)")
	} else {
		log.Info().Msg("TTL index for token_cache collection ensured.")
	}

	return store
}

// toDocument converts a cache.TokenEntry into a tokenCacheDocument for storage.
func (s *MongoTokenStore) toDocument(entry *cache.TokenEntry) *tokenCacheDocument {
	return &tokenCacheDocument{
		ID:         cache.HashToken(entry.TokenValue),
		TokenType:  entry.TokenType,
		TokenValue: entry.TokenValue,
		ClientID:   entry.ClientID,
		UserID:     entry.UserID,
		Scope:      entry.Scope,
		ExpiresAt:  entry.ExpiresAt,
		IsRevoked:  entry.IsRevoked,
		CreatedAt:  entry.CreatedAt,
		LastUsedAt: entry.LastUsedAt,
		Roles:      entry.Roles,
	}
}

// fromDocument converts a tokenCacheDocument back into a cache.TokenEntry.
func (s *MongoTokenStore) fromDocument(doc *tokenCacheDocument) *cache.TokenEntry {
	return &cache.TokenEntry{
		TokenValue: doc.TokenValue,
		TokenType:  doc.TokenType,
		ClientID:   doc.ClientID,
		UserID:     doc.UserID,
		Scope:      doc.Scope,
		ExpiresAt:  doc.ExpiresAt,
		IsRevoked:  doc.IsRevoked,
		CreatedAt:  doc.CreatedAt,
		LastUsedAt: doc.LastUsedAt,
		Roles:      doc.Roles,
	}
}

// Set stores a token entry, upserting by the hashed token value.
func (s *MongoTokenStore) Set(ctx context.Context, entry *cache.TokenEntry) error {
	doc := s.toDocument(entry)
	filter := bson.M{"_id": doc.ID}
	opts := options.Replace().SetUpsert(true)
	_, err := s.collection.ReplaceOne(ctx, filter, doc, opts)
	if err != nil {
		log.Debug().Err(err).Str("tokenHash", doc.ID).Msg("Failed to set token in MongoDB")
		return err
	}
	return nil
}

// Get retrieves a token entry by its raw token value (hashed for lookup).
// Returns (nil, nil) if the token is not found.
func (s *MongoTokenStore) Get(ctx context.Context, token string) (*cache.TokenEntry, error) {
	tokenHash := cache.HashToken(token)

	var doc tokenCacheDocument
	err := s.collection.FindOne(ctx, bson.M{"_id": tokenHash}).Decode(&doc)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, nil
		}
		log.Debug().Err(err).Str("tokenHash", tokenHash).Msg("Failed to get token from MongoDB")
		return nil, err
	}

	doc.LastUsedAt = time.Now()
	_, updateErr := s.collection.UpdateOne(ctx, bson.M{"_id": doc.ID}, bson.M{"$set": bson.M{"last_used_at": time.Now()}})
	if updateErr != nil {
		log.Debug().Err(updateErr).Str("tokenHash", tokenHash).Msg("Failed to update last_used_at in MongoDB")
	}

	return s.fromDocument(&doc), nil
}

// Delete removes a token by its raw token value (hashed for lookup).
func (s *MongoTokenStore) Delete(ctx context.Context, token string) error {
	tokenHash := cache.HashToken(token)
	_, err := s.collection.DeleteOne(ctx, bson.M{"_id": tokenHash})
	if err != nil {
		log.Debug().Err(err).Str("tokenHash", tokenHash).Msg("Failed to delete token from MongoDB")
		return err
	}
	return nil
}

// DeleteExpired removes all expired tokens from the collection.
func (s *MongoTokenStore) DeleteExpired(ctx context.Context) error {
	now := time.Now()
	_, err := s.collection.DeleteMany(ctx, bson.M{"expires_at": bson.M{"$lte": now}})
	if err != nil {
		log.Debug().Err(err).Msg("Failed to delete expired tokens from MongoDB")
		return err
	}
	return nil
}

// Clear removes all token documents from the collection.
func (s *MongoTokenStore) Clear(ctx context.Context) error {
	_, err := s.collection.DeleteMany(ctx, bson.M{})
	if err != nil {
		log.Debug().Err(err).Msg("Failed to clear token cache in MongoDB")
		return err
	}
	return nil
}

// Count returns the estimated number of token documents in the collection.
func (s *MongoTokenStore) Count(ctx context.Context) int {
	count, err := s.collection.EstimatedDocumentCount(ctx)
	if err != nil {
		log.Debug().Err(err).Msg("Failed to count token cache documents in MongoDB")
		return 0
	}
	return int(count)
}

// Ensure interface compliance.
var _ cache.TokenStore = (*MongoTokenStore)(nil)
