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

// SessionRepositoryMongo implements the domain.SessionRepository interface using MongoDB.
type SessionRepositoryMongo struct {
	collection *mongo.Collection
}

// NewSessionRepositoryMongo creates a new SessionRepositoryMongo.
// It also ensures that necessary indexes are created on the collection.
func NewSessionRepositoryMongo(ctx context.Context, db *mongo.Database) (domain.SessionRepository, error) {
	repo := &SessionRepositoryMongo{
		collection: db.Collection(UserSessionsCollection), // "oauth_user_sessions"
	}

	indexModels := []mongo.IndexModel{
		// {
		// 	Keys:    bson.D{{Key: "_id", Value: 1}}, // Session ID
		// 	Options: options.Index().SetUnique(true),
		// },
		{
			Keys:    bson.D{{Key: "token_id", Value: 1}},             // JWT JTI, should be unique if used as main lookup
			Options: options.Index().SetUnique(true).SetSparse(true), // Sparse if not all sessions have it
		},
		{
			Keys:    bson.D{{Key: "user_id", Value: 1}},
			Options: options.Index(), // Not unique, user can have multiple sessions
		},
		{
			Keys:    bson.D{{Key: "expires_at", Value: 1}},
			Options: options.Index().SetExpireAfterSeconds(0), // TTL index for automatic cleanup
		},
		{
			Keys:    bson.D{{Key: "is_revoked", Value: 1}},
			Options: options.Index(),
		},
	}

	opts := options.CreateIndexes()
	_, err := repo.collection.Indexes().CreateMany(ctx, indexModels, opts)
	if err != nil {
		// Log and continue or return error based on desired strictness
		log.Warn().Err(err).Msg("Issue creating indexes for user_sessions collection (might already exist or other error)")
		// return nil, fmt.Errorf("failed to create session indexes: %w", err) // Stricter option
	} else {
		log.Info().Msg("Indexes for user_sessions collection ensured.")
	}

	return repo, nil
}

// StoreSession creates a new session.
func (r *SessionRepositoryMongo) StoreSession(ctx context.Context, session *domain.Session) error {
	if session.ID == "" {
		session.ID = NewObjectID() // Generate new ID if not provided
	}
	if session.CreatedAt.IsZero() {
		session.CreatedAt = time.Now().UTC()
	}
	// ExpiresAt should be set by the caller (AuthService)

	_, err := r.collection.InsertOne(ctx, session)
	if err != nil {
		if mongo.IsDuplicateKeyError(err) {
			return errors.New("session with this ID or TokenID already exists")
		}
		log.Error().Err(err).Msg("Error storing session in MongoDB")
		return err
	}
	return nil
}

// GetSessionByID retrieves a session by its primary ID.
func (r *SessionRepositoryMongo) GetSessionByID(ctx context.Context, id string) (*domain.Session, error) {
	var session domain.Session
	err := r.collection.FindOne(ctx, bson.M{"_id": id}).Decode(&session)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, errors.New("session not found by ID")
		}
		log.Error().Err(err).Str("id", id).Msg("Error getting session by ID from MongoDB")
		return nil, err
	}
	return &session, nil
}

// GetSessionByTokenID retrieves a session by its TokenID (e.g., JWT JTI).
func (r *SessionRepositoryMongo) GetSessionByTokenID(ctx context.Context, tokenID string) (*domain.Session, error) {
	var session domain.Session
	err := r.collection.FindOne(ctx, bson.M{"token_id": tokenID}).Decode(&session)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, errors.New("session not found by TokenID")
		}
		log.Error().Err(err).Str("tokenID", tokenID).Msg("Error getting session by TokenID from MongoDB")
		return nil, err
	}
	return &session, nil
}

// UpdateSession updates an existing session, e.g., to mark it as revoked.
func (r *SessionRepositoryMongo) UpdateSession(ctx context.Context, session *domain.Session) error {
	if session.ID == "" {
		return errors.New("session ID is required for update")
	}
	filter := bson.M{"_id": session.ID}
	// Example: update IsRevoked and ExpiresAt if needed
	update := bson.M{"$set": bson.M{
		"is_revoked": session.IsRevoked,
		"expires_at": session.ExpiresAt, // Allow extending or shortening session
		// Potentially other fields like UserAgent, IPAddress if they can change post-creation
	}}
	result, err := r.collection.UpdateOne(ctx, filter, update)
	if err != nil {
		log.Error().Err(err).Str("sessionID", session.ID).Msg("Error updating session in MongoDB")
		return err
	}
	if result.MatchedCount == 0 {
		return errors.New("session not found for update")
	}
	return nil
}

// DeleteSession removes a session by its ID.
func (r *SessionRepositoryMongo) DeleteSession(ctx context.Context, id string) error {
	result, err := r.collection.DeleteOne(ctx, bson.M{"_id": id})
	if err != nil {
		log.Error().Err(err).Str("id", id).Msg("Error deleting session from MongoDB")
		return err
	}
	if result.DeletedCount == 0 {
		return errors.New("session not found for deletion")
	}
	return nil
}

// ListSessionsByUserID retrieves sessions for a user, optionally filtered.
func (r *SessionRepositoryMongo) ListSessionsByUserID(ctx context.Context, userID string, filter domain.SessionFilter) ([]*domain.Session, error) {
	mongoFilter := bson.M{"user_id": userID}
	if filter.IPAddress != "" {
		mongoFilter["ip_address"] = filter.IPAddress
	}
	if filter.UserAgent != "" {
		// May need regex for partial matches if UserAgent is complex
		mongoFilter["user_agent"] = filter.UserAgent
	}
	if !filter.FromDate.IsZero() || !filter.ToDate.IsZero() {
		dateFilter := bson.M{}
		if !filter.FromDate.IsZero() {
			dateFilter["$gte"] = filter.FromDate
		}
		if !filter.ToDate.IsZero() {
			dateFilter["$lte"] = filter.ToDate
		}
		mongoFilter["created_at"] = dateFilter // Or use 'expires_at' or another relevant date field
	}
	if filter.IsRevoked != nil {
		mongoFilter["is_revoked"] = *filter.IsRevoked
	}

	cursor, err := r.collection.Find(ctx, mongoFilter, options.Find().SetSort(bson.D{{"created_at", -1}}))
	if err != nil {
		log.Error().Err(err).Str("userID", userID).Msg("Error listing sessions by user ID from MongoDB")
		return nil, err
	}
	defer cursor.Close(ctx)

	var sessions []*domain.Session
	if err = cursor.All(ctx, &sessions); err != nil {
		log.Error().Err(err).Msg("Error decoding listed sessions from MongoDB")
		return nil, err
	}
	return sessions, nil
}

// DeleteSessionsByUserID removes all sessions for a given user, optionally keeping some.
func (r *SessionRepositoryMongo) DeleteSessionsByUserID(ctx context.Context, userID string, exceptSessionIDs ...string) (int64, error) {
	filter := bson.M{"user_id": userID}
	if len(exceptSessionIDs) > 0 {
		filter["_id"] = bson.M{"$nin": exceptSessionIDs}
	}

	result, err := r.collection.DeleteMany(ctx, filter)
	if err != nil {
		log.Error().Err(err).Str("userID", userID).Msg("Error deleting sessions by user ID from MongoDB")
		return 0, err
	}
	return result.DeletedCount, nil
}

// Ensure interface compliance
var _ domain.SessionRepository = (*SessionRepositoryMongo)(nil)
