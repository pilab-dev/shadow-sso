package mongodb

import (
	"context"
	"fmt"
	"time"

	ssso "github.com/pilab-dev/shadow-sso"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type UserRepository struct {
	db       *mongo.Database
	users    *mongo.Collection
	sessions *mongo.Collection
}

func NewUserRepository(ctx context.Context, db *mongo.Database) (ssso.UserRepository, error) {
	repo := &UserRepository{
		db:       db,
		users:    db.Collection("users"),
		sessions: db.Collection("sessions"),
	}

	// Create indexes
	if err := repo.createIndexes(ctx); err != nil {
		return nil, err
	}

	return repo, nil
}

func (r *UserRepository) createIndexes(ctx context.Context) error {
	// Username unique index
	_, err := r.users.Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys: bson.D{{Key: "username", Value: 1}},
		Options: options.Index().
			SetUnique(true).
			SetCollation(&options.Collation{Locale: "en", Strength: 2}),
	})
	if err != nil {
		return fmt.Errorf("failed to create username index: %w", err)
	}

	// Session indexes
	_, err = r.sessions.Indexes().CreateMany(ctx, []mongo.IndexModel{
		{
			Keys: bson.D{{Key: "user_id", Value: 1}},
		},
		{
			Keys:    bson.D{{Key: "access_token", Value: 1}},
			Options: options.Index().SetUnique(true),
		},
		{
			Keys:    bson.D{{Key: "expires_at", Value: 1}},
			Options: options.Index().SetExpireAfterSeconds(0),
		},
	})
	return err
}

func (r *UserRepository) CreateUser(ctx context.Context, username, password string) (*ssso.User, error) {
	user := &ssso.User{
		ID:        NewObjectID(),
		Username:  username,
		Password:  password,
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}

	_, err := r.users.InsertOne(ctx, user)
	if err != nil {
		if mongo.IsDuplicateKeyError(err) {
			return nil, fmt.Errorf("username already exists")
		}
		return nil, err
	}

	return user, nil
}

func (r *UserRepository) GetUserByID(ctx context.Context, id string) (*ssso.User, error) {
	var user ssso.User
	err := r.users.FindOne(ctx, bson.M{"_id": id}).Decode(&user)
	if err == mongo.ErrNoDocuments {
		return nil, fmt.Errorf("user not found")
	}
	return &user, err
}

func (r *UserRepository) GetUserByUsername(ctx context.Context, username string) (*ssso.User, error) {
	var user ssso.User
	err := r.users.FindOne(ctx, bson.M{"username": username}).Decode(&user)
	if err == mongo.ErrNoDocuments {
		return nil, fmt.Errorf("user not found")
	}
	return &user, err
}

func (r *UserRepository) UpdateUser(ctx context.Context, user *ssso.User) error {
	user.UpdatedAt = time.Now().UTC()
	_, err := r.users.ReplaceOne(ctx, bson.M{"_id": user.ID}, user)
	return err
}

func (r *UserRepository) DeleteUser(ctx context.Context, id string) error {
	_, err := r.users.DeleteOne(ctx, bson.M{"_id": id})
	return err
}

func (r *UserRepository) CreateSession(ctx context.Context, userID string, session *ssso.UserSession) error {
	_, err := r.sessions.InsertOne(ctx, session)
	return err
}

func (r *UserRepository) GetUserSessions(ctx context.Context, userID string) ([]ssso.UserSession, error) {
	cursor, err := r.sessions.Find(ctx, bson.M{
		"user_id":    userID,
		"is_revoked": false,
		"expires_at": bson.M{"$gt": time.Now().UTC()},
	})
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var sessions []ssso.UserSession
	if err := cursor.All(ctx, &sessions); err != nil {
		return nil, err
	}

	return sessions, nil
}

func (r *UserRepository) GetSessionByToken(ctx context.Context, accessToken string) (*ssso.UserSession, error) {
	var session ssso.UserSession
	err := r.sessions.FindOne(ctx, bson.M{
		"access_token": accessToken,
		"is_revoked":   false,
		"expires_at":   bson.M{"$gt": time.Now().UTC()},
	}).Decode(&session)
	if err == mongo.ErrNoDocuments {
		return nil, fmt.Errorf("session not found")
	}
	return &session, err
}

func (r *UserRepository) UpdateSessionLastUsed(ctx context.Context, sessionID string) error {
	_, err := r.sessions.UpdateOne(ctx,
		bson.M{"_id": sessionID},
		bson.M{"$set": bson.M{"last_used_at": time.Now().UTC()}},
	)
	return err
}

func (r *UserRepository) RevokeSession(ctx context.Context, sessionID string) error {
	_, err := r.sessions.UpdateOne(ctx,
		bson.M{"_id": sessionID},
		bson.M{"$set": bson.M{"is_revoked": true}},
	)
	return err
}

func (r *UserRepository) DeleteExpiredSessions(ctx context.Context, userID string) error {
	_, err := r.sessions.DeleteMany(ctx, bson.M{
		"user_id": userID,
		"$or": []bson.M{
			{"expires_at": bson.M{"$lt": time.Now().UTC()}},
			{"is_revoked": true},
		},
	})
	return err
}

func (r *UserRepository) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	return r.db.Client().Disconnect(ctx)
}
