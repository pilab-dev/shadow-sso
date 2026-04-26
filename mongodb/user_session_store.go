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

// UserSessionsOIDCCollection is the MongoDB collection name for OIDC user sessions.
// This is distinct from UserSessionsCollection ("oauth_user_sessions") used by
// the domain.SessionRepository.
const UserSessionsOIDCCollection = "user_sessions_oidc"

// MongoUserSessionStore implements domain.UserSessionStore using MongoDB.
type MongoUserSessionStore struct {
	collection *mongo.Collection
}

// NewUserSessionStore creates a new MongoUserSessionStore and ensures the TTL index on expires_at.
func NewUserSessionStore(db *mongo.Database) *MongoUserSessionStore {
	repo := &MongoUserSessionStore{
		collection: db.Collection(UserSessionsOIDCCollection),
	}

	ctx := context.Background()
	indexModels := []mongo.IndexModel{
		{
			Keys:    bson.D{{Key: "expires_at", Value: 1}},
			Options: options.Index().SetExpireAfterSeconds(0),
		},
	}
	opts := options.CreateIndexes()
	if _, err := repo.collection.Indexes().CreateMany(ctx, indexModels, opts); err != nil {
		log.Warn().Err(err).Msg("Issue creating indexes for user_sessions_oidc collection (might already exist or other error)")
	} else {
		log.Info().Msg("Indexes for user_sessions_oidc collection ensured.")
	}

	return repo
}

// StoreUserSession inserts a new user session. If SessionID is empty, it is
// auto-generated using NewID(). SessionID becomes _id via the bson tag.
func (s *MongoUserSessionStore) StoreUserSession(ctx context.Context, session *domain.UserSession) error {
	if session.SessionID == "" {
		session.SessionID = NewID()
	}

	if _, err := s.collection.InsertOne(ctx, session); err != nil {
		log.Debug().Err(err).Str("sessionID", session.SessionID).Msg("Failed to store user session")
		return err
	}
	return nil
}

// GetUserSession retrieves a user session by its ID.
// Returns ErrSessionNotFound if the document does not exist,
// or ErrSessionExpired if the session has expired.
func (s *MongoUserSessionStore) GetUserSession(ctx context.Context, sessionID string) (*domain.UserSession, error) {
	var session domain.UserSession
	if err := s.collection.FindOne(ctx, bson.M{"_id": sessionID}).Decode(&session); err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, domain.ErrSessionNotFound
		}
		log.Debug().Err(err).Str("sessionID", sessionID).Msg("Failed to get user session")
		return nil, err
	}

	if time.Now().After(session.ExpiresAt) {
		return &session, domain.ErrSessionExpired
	}

	return &session, nil
}

// DeleteUserSession removes a user session by its ID.
// Returns ErrSessionNotFound if no matching session is found.
func (s *MongoUserSessionStore) DeleteUserSession(ctx context.Context, sessionID string) error {
	result, err := s.collection.DeleteOne(ctx, bson.M{"_id": sessionID})
	if err != nil {
		log.Debug().Err(err).Str("sessionID", sessionID).Msg("Failed to delete user session")
		return err
	}
	if result.DeletedCount == 0 {
		return domain.ErrSessionNotFound
	}

	return nil
}

// CleanupExpiredSessions is a no-op. The TTL index on expires_at handles automatic cleanup.
func (s *MongoUserSessionStore) CleanupExpiredSessions() {
	// No-op: TTL index on expires_at automatically removes expired documents.
}

// Ensure interface compliance.
var _ domain.UserSessionStore = (*MongoUserSessionStore)(nil)