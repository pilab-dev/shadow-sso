package mongodb

import (
	"context"
	"errors"
	"time"

	"github.com/pilab-dev/shadow-sso/domain"
	"github.com/rs/zerolog/log"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

// PublicKeyRepositoryMongo implements the domain.PublicKeyRepository interface using MongoDB.
type PublicKeyRepositoryMongo struct {
	collection *mongo.Collection
}

// NewPublicKeyRepositoryMongo creates a new PublicKeyRepositoryMongo.
// It also ensures that the necessary indexes are created on the collection.
func NewPublicKeyRepositoryMongo(db *mongo.Database) (*PublicKeyRepositoryMongo, error) {
	repo := &PublicKeyRepositoryMongo{
		collection: db.Collection(PublicKeysCollection),
	}

	// Create indexes
    // Index on key_id for fast lookups by GetPublicKey
	// Index on service_account_id for listing keys per SA (if that method is added)
	// Index on status for querying active/revoked keys
	indexModels := []mongo.IndexModel{
		{
			Keys:    bson.D{{Key: "_id", Value: 1}}, // _id is keyID (private_key_id)
			Options: options.Index().SetUnique(true),
		},
		{
			Keys:    bson.D{{Key: "service_account_id", Value: 1}},
			Options: options.Index().SetUnique(false), // Not unique as one SA can have multiple keys
		},
        {
			Keys:    bson.D{{Key: "status", Value: 1}},
			Options: options.Index().SetUnique(false),
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_, err := repo.collection.Indexes().CreateMany(ctx, indexModels)
	if err != nil {
		log.Error().Err(err).Msg("Failed to create indexes for public_keys collection")
		return nil, err
	}
	log.Info().Msg("Indexes for public_keys collection ensured.")
	return repo, nil
}

// GetPublicKey retrieves active public key information by its ID (kid).
// In our domain.PublicKeyInfo, ID field is the keyID.
func (r *PublicKeyRepositoryMongo) GetPublicKey(ctx context.Context, keyID string) (*domain.PublicKeyInfo, error) {
	var pubKeyInfo domain.PublicKeyInfo
	// We store keyID directly in _id field of PublicKeyInfo for MongoDB.
	err := r.collection.FindOne(ctx, bson.M{"_id": keyID, "status": "ACTIVE"}).Decode(&pubKeyInfo)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, errors.New("public key not found or not active") // Or a more specific error type
		}
		log.Error().Err(err).Str("keyID", keyID).Msg("Error retrieving public key from MongoDB")
		return nil, err
	}
	return &pubKeyInfo, nil
}

// CreatePublicKey stores a new public key.
// This method would be used by the ServiceAccountService when a new key is generated.
func (r *PublicKeyRepositoryMongo) CreatePublicKey(ctx context.Context, pubKeyInfo *domain.PublicKeyInfo) error {
	if pubKeyInfo.ID == "" {
        // The ID for PublicKeyInfo is the private_key_id from the service account JSON key.
        // It should be set by the caller (ServiceAccountService logic).
		return errors.New("public key info ID (keyID) cannot be empty")
	}
    if pubKeyInfo.CreatedAt == 0 { // Assuming 0 is uninitialized for int64 timestamp
        pubKeyInfo.CreatedAt = time.Now().Unix()
    }
    if pubKeyInfo.Status == "" {
        pubKeyInfo.Status = "ACTIVE" // Default to ACTIVE
    }

    // Using pubKeyInfo.ID as MongoDB's _id field.
	_, err := r.collection.InsertOne(ctx, pubKeyInfo)
	if err != nil {
		log.Error().Err(err).Msg("Error inserting public key into MongoDB")
		// Handle potential duplicate key error if _id is not unique, though index should cover this.
		return err
	}
	return nil
}

// UpdatePublicKeyStatus updates the status (and potentially other fields) of a public key.
// Useful for revoking a key.
func (r *PublicKeyRepositoryMongo) UpdatePublicKeyStatus(ctx context.Context, keyID string, newStatus string) error {
	filter := bson.M{"_id": keyID}
	update := bson.M{"$set": bson.M{"status": newStatus, "updated_at": time.Now().Unix()}} // Add updated_at if it's in PublicKeyInfo

	result, err := r.collection.UpdateOne(ctx, filter, update)
	if err != nil {
		log.Error().Err(err).Str("keyID", keyID).Msg("Error updating public key status in MongoDB")
		return err
	}
	if result.MatchedCount == 0 {
		return errors.New("public key not found for status update") // Or a domain specific error
	}
	return nil
}

// ListPublicKeysForServiceAccount retrieves all public keys (or active ones) for a given service account ID.
// This is an example of another useful method.
func (r *PublicKeyRepositoryMongo) ListPublicKeysForServiceAccount(ctx context.Context, serviceAccountID string, onlyActive bool) ([]*domain.PublicKeyInfo, error) {
    filter := bson.M{"service_account_id": serviceAccountID}
    if onlyActive {
        filter["status"] = "ACTIVE"
    }

    cursor, err := r.collection.Find(ctx, filter)
    if err != nil {
        log.Error().Err(err).Str("serviceAccountID", serviceAccountID).Msg("Error finding public keys for service account")
        return nil, err
    }
    defer cursor.Close(ctx)

    var keys []*domain.PublicKeyInfo
    if err = cursor.All(ctx, &keys); err != nil {
        log.Error().Err(err).Msg("Error decoding public keys for service account")
        return nil, err
    }
    return keys, nil
}

// Ensure PublicKeyRepositoryMongo implements domain.PublicKeyRepository
var _ domain.PublicKeyRepository = (*PublicKeyRepositoryMongo)(nil)
