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

// FlowStatesCollection is the MongoDB collection name for login flow states.
const FlowStatesCollection = "flow_states"

// MongoFlowStore implements domain.FlowStore using MongoDB.
type MongoFlowStore struct {
	collection *mongo.Collection
}

// NewFlowStore creates a new MongoFlowStore and ensures the TTL index on expires_at.
func NewFlowStore(ctx context.Context, db *mongo.Database) *MongoFlowStore {
	repo := &MongoFlowStore{
		collection: db.Collection(FlowStatesCollection),
	}

	indexModels := []mongo.IndexModel{
		{
			Keys:    bson.D{{Key: "expires_at", Value: 1}},
			Options: options.Index().SetExpireAfterSeconds(0),
		},
	}
	opts := options.CreateIndexes()
	if _, err := repo.collection.Indexes().CreateMany(ctx, indexModels, opts); err != nil {
		log.Warn().Err(err).Msg("Issue creating indexes for flow_states collection (might already exist or other error)")
	} else {
		log.Info().Msg("Indexes for flow_states collection ensured.")
	}

	return repo
}

// StoreFlow inserts a new login flow state. FlowID becomes _id via the bson tag.
func (s *MongoFlowStore) StoreFlow(ctx context.Context, flowID string, state domain.LoginFlowState) error {
	if _, err := s.collection.InsertOne(ctx, state); err != nil {
		log.Debug().Err(err).Str("flowID", flowID).Msg("Failed to store login flow state")
		return err
	}
	return nil
}

// GetFlow retrieves a login flow state by its ID.
// Returns ErrFlowNotFound if the document does not exist,
// or ErrFlowExpired if the state has expired.
func (s *MongoFlowStore) GetFlow(ctx context.Context, flowID string) (*domain.LoginFlowState, error) {
	var state domain.LoginFlowState
	if err := s.collection.FindOne(ctx, bson.M{"_id": flowID}).Decode(&state); err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, domain.ErrFlowNotFound
		}
		log.Debug().Err(err).Str("flowID", flowID).Msg("Failed to get login flow state")
		return nil, err
	}

	if time.Now().After(state.ExpiresAt) {
		return &state, domain.ErrFlowExpired
	}

	return &state, nil
}

// UpdateFlow updates an existing login flow state identified by flowID.
// Returns ErrFlowNotFound if no matching flow state is found.
func (s *MongoFlowStore) UpdateFlow(ctx context.Context, flowID string, state *domain.LoginFlowState) error {
	filter := bson.M{"_id": flowID}
	update := bson.M{"$set": state}

	result, err := s.collection.UpdateOne(ctx, filter, update)
	if err != nil {
		log.Debug().Err(err).Str("flowID", flowID).Msg("Failed to update login flow state")
		return err
	}
	if result.MatchedCount == 0 {
		return domain.ErrFlowNotFound
	}

	return nil
}

// DeleteFlow removes a login flow state by its ID.
// Returns ErrFlowNotFound if no matching flow state is found.
func (s *MongoFlowStore) DeleteFlow(ctx context.Context, flowID string) error {
	result, err := s.collection.DeleteOne(ctx, bson.M{"_id": flowID})
	if err != nil {
		log.Debug().Err(err).Str("flowID", flowID).Msg("Failed to delete login flow state")
		return err
	}
	if result.DeletedCount == 0 {
		return domain.ErrFlowNotFound
	}

	return nil
}

// CleanupExpiredFlows is a no-op. The TTL index on expires_at handles automatic cleanup.
func (s *MongoFlowStore) CleanupExpiredFlows() {
	// No-op: TTL index on expires_at automatically removes expired documents.
}

// Ensure interface compliance.
var _ domain.FlowStore = (*MongoFlowStore)(nil)
