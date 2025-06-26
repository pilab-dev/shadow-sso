package mongodb

import (
	"context"
	"fmt"

	"github.com/rs/zerolog/log"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

// DatabaseIndexer is a struct wich handles initial database indexing.
type DatabaseIndexer struct {
	db         *mongo.Database
	clients    *mongo.Collection
	tokens     *mongo.Collection
	sessions   *mongo.Collection
	authCodes  *mongo.Collection
	challenges *mongo.Collection
}

// NewDatabaseIndexer initializes a new DatabaseIndexer.
func NewDatabaseIndexer(ctx context.Context, db *mongo.Database) (*DatabaseIndexer, error) {
	repo := &DatabaseIndexer{
		db:         db,
		clients:    db.Collection(ClientsCollection),
		tokens:     db.Collection(TokensCollection),
		sessions:   db.Collection(UserSessionsCollection),
		authCodes:  db.Collection(CodesCollection),
		challenges: db.Collection(ChallengesCollection),
	}

	if err := repo.createIndexes(ctx); err != nil {
		return nil, err
	}

	return repo, nil
}

func (r *DatabaseIndexer) createIndexes(ctx context.Context) error {
	_, err := r.clients.Indexes().CreateMany(ctx, []mongo.IndexModel{
		{
			Keys:    bson.D{{Key: "client_id", Value: 1}},
			Options: options.Index().SetUnique(true),
		},
	})
	if err != nil {
		log.Warn().Err(err).Msg("Issue creating client_id index (may already exist or other benign issue)")
	}

	_, err = r.authCodes.Indexes().CreateMany(ctx, []mongo.IndexModel{
		{Keys: bson.D{{Key: "code", Value: 1}}, Options: options.Index().SetUnique(true)},
		{Keys: bson.D{{Key: "expires_at", Value: 1}}, Options: options.Index().SetExpireAfterSeconds(0)},
	})
	if err != nil {
		return fmt.Errorf("failed to create auth_code indexes: %w", err)
	}

	_, err = r.tokens.Indexes().CreateMany(ctx, []mongo.IndexModel{
		{Keys: bson.D{{Key: "token_value", Value: 1}}, Options: options.Index().SetUnique(true)},
		{Keys: bson.D{{Key: "expires_at", Value: 1}}, Options: options.Index().SetExpireAfterSeconds(0)},
		{Keys: bson.D{{Key: "user_id", Value: 1}}},
		{Keys: bson.D{{Key: "client_id", Value: 1}}},
	})
	if err != nil {
		return fmt.Errorf("failed to create token indexes: %w", err)
	}

	_, err = r.challenges.Indexes().CreateMany(ctx, []mongo.IndexModel{
		{Keys: bson.D{{Key: "code", Value: 1}}, Options: options.Index().SetUnique(true)},
		{Keys: bson.D{{Key: "created_at", Value: 1}}, Options: options.Index().SetExpireAfterSeconds(600)},
	})
	if err != nil {
		return fmt.Errorf("failed to create challenges indexes: %w", err)
	}

	_, err = r.sessions.Indexes().CreateMany(ctx, []mongo.IndexModel{
		{Keys: bson.D{{Key: "_id", Value: 1}}, Options: options.Index().SetUnique(true)},
		{Keys: bson.D{{Key: "token_id", Value: 1}}, Options: options.Index().SetUnique(true).SetSparse(true)},
		{Keys: bson.D{{Key: "user_id", Value: 1}}},
		{Keys: bson.D{{Key: "expires_at", Value: 1}}, Options: options.Index().SetExpireAfterSeconds(0)},
	})
	if err != nil {
		return fmt.Errorf("failed to create session indexes: %w", err)
	}

	log.Info().Msg("All repository indexes ensured.")

	return nil
}
