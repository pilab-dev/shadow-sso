package mongodb

import (
	"context"
	"fmt"
	"time"

	"github.com/pilab-dev/shadow-sso/domain"
	"github.com/rs/zerolog/log"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

// PkceChallengesCollection is the MongoDB collection name for standalone PKCE challenges.
// This is a separate collection from ChallengesCollection ("oauth_pkce_challenges")
// used by AuthCodeRepository's hybrid PKCE methods.
const PkceChallengesCollection = "pkce_challenges"

// pkceDocument represents a PKCE challenge stored in MongoDB.
type pkceDocument struct {
	Code      string    `bson:"_id"`
	Challenge string    `bson:"challenge"`
	CreatedAt time.Time `bson:"created_at"`
}

// MongoPkceRepository implements domain.PkceRepository using MongoDB.
type MongoPkceRepository struct {
	collection *mongo.Collection
}

// NewPkceRepository creates a new MongoPkceRepository and ensures a TTL index
// on created_at that expires documents after 10 minutes.
func NewPkceRepository(ctx context.Context, db *mongo.Database) *MongoPkceRepository {
	repo := &MongoPkceRepository{
		collection: db.Collection(PkceChallengesCollection),
	}

	indexModels := []mongo.IndexModel{
		{
			Keys:    bson.D{{Key: "created_at", Value: 1}},
			Options: options.Index().SetExpireAfterSeconds(600),
		},
	}
	opts := options.CreateIndexes()
	if _, err := repo.collection.Indexes().CreateMany(ctx, indexModels, opts); err != nil {
		log.Warn().Err(err).Msg("Issue creating TTL index for pkce_challenges collection (might already exist or other error)")
	} else {
		log.Info().Msg("TTL index for pkce_challenges collection ensured.")
	}

	return repo
}

// SaveCodeChallenge stores a PKCE code challenge. The code is used as the document _id.
func (r *MongoPkceRepository) SaveCodeChallenge(ctx context.Context, code, challenge string) error {
	doc := pkceDocument{
		Code:      code,
		Challenge: challenge,
		CreatedAt: time.Now().UTC(),
	}
	if _, err := r.collection.InsertOne(ctx, doc); err != nil {
		log.Debug().Err(err).Str("code", code).Msg("Failed to save PKCE code challenge")
		return err
	}
	return nil
}

// GetCodeChallenge retrieves the challenge for a given code.
// Returns an error if the code is not found.
func (r *MongoPkceRepository) GetCodeChallenge(ctx context.Context, code string) (string, error) {
	var doc pkceDocument
	if err := r.collection.FindOne(ctx, bson.M{"_id": code}).Decode(&doc); err != nil {
		if err == mongo.ErrNoDocuments {
			return "", fmt.Errorf("code challenge not found for code: %s", code)
		}
		log.Debug().Err(err).Str("code", code).Msg("Failed to get PKCE code challenge")
		return "", err
	}
	return doc.Challenge, nil
}

// DeleteCodeChallenge removes a PKCE code challenge by its code.
func (r *MongoPkceRepository) DeleteCodeChallenge(ctx context.Context, code string) error {
	result, err := r.collection.DeleteOne(ctx, bson.M{"_id": code})
	if err != nil {
		log.Debug().Err(err).Str("code", code).Msg("Failed to delete PKCE code challenge")
		return err
	}
	if result.DeletedCount == 0 {
		log.Warn().Str("code", code).Msg("No PKCE code challenge found to delete")
	}
	return nil
}

// Ensure interface compliance.
var _ domain.PkceRepository = (*MongoPkceRepository)(nil)