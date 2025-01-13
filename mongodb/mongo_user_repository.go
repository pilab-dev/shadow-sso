package mongodb

import (
	"context"
	"fmt"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.opentelemetry.io/contrib/instrumentation/go.mongodb.org/mongo-driver/mongo/otelmongo"
	"go.pilab.hu/sso"
)

type MongoUserRepository struct {
	db         *mongo.Database
	users      *mongo.Collection
	sessions   *mongo.Collection
	ctx        context.Context
	cancelFunc context.CancelFunc
}

func NewMongoUserRepository(uri string, dbName string) (*MongoUserRepository, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	opts := options.Client().ApplyURI(uri).SetMonitor(otelmongo.NewMonitor())
	client, err := mongo.Connect(ctx, opts)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("failed to connect to MongoDB: %w", err)
	}

	db := client.Database(dbName)
	repo := &MongoUserRepository{
		db:         db,
		users:      db.Collection("users"),
		sessions:   db.Collection("sessions"),
		ctx:        ctx,
		cancelFunc: cancel,
	}

	// Create indexes
	if err := repo.createIndexes(); err != nil {
		cancel()
		return nil, err
	}

	return repo, nil
}

func (r *MongoUserRepository) createIndexes() error {
	// Username unique index
	_, err := r.users.Indexes().CreateOne(r.ctx, mongo.IndexModel{
		Keys: bson.D{{Key: "username", Value: 1}},
		Options: options.Index().
			SetUnique(true).
			SetCollation(&options.Collation{Locale: "en", Strength: 2}),
	})
	if err != nil {
		return fmt.Errorf("failed to create username index: %w", err)
	}

	// Session indexes
	_, err = r.sessions.Indexes().CreateMany(r.ctx, []mongo.IndexModel{
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

func (r *MongoUserRepository) CreateUser(username, password string) (*sso.User, error) {
	user := &sso.User{
		ID:        NewObjectID(),
		Username:  username,
		Password:  password,
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}

	_, err := r.users.InsertOne(r.ctx, user)
	if err != nil {
		if mongo.IsDuplicateKeyError(err) {
			return nil, fmt.Errorf("username already exists")
		}
		return nil, err
	}

	return user, nil
}

func (r *MongoUserRepository) GetUserByID(id string) (*sso.User, error) {
	var user sso.User
	err := r.users.FindOne(r.ctx, bson.M{"_id": id}).Decode(&user)
	if err == mongo.ErrNoDocuments {
		return nil, fmt.Errorf("user not found")
	}
	return &user, err
}

func (r *MongoUserRepository) GetUserByUsername(username string) (*sso.User, error) {
	var user sso.User
	err := r.users.FindOne(r.ctx, bson.M{"username": username}).Decode(&user)
	if err == mongo.ErrNoDocuments {
		return nil, fmt.Errorf("user not found")
	}
	return &user, err
}

func (r *MongoUserRepository) UpdateUser(user *sso.User) error {
	user.UpdatedAt = time.Now().UTC()
	_, err := r.users.ReplaceOne(r.ctx, bson.M{"_id": user.ID}, user)
	return err
}

func (r *MongoUserRepository) DeleteUser(id string) error {
	_, err := r.users.DeleteOne(r.ctx, bson.M{"_id": id})
	return err
}

func (r *MongoUserRepository) CreateSession(userID string, session *sso.UserSession) error {
	_, err := r.sessions.InsertOne(r.ctx, session)
	return err
}

func (r *MongoUserRepository) GetUserSessions(userID string) ([]sso.UserSession, error) {
	cursor, err := r.sessions.Find(r.ctx, bson.M{
		"user_id":    userID,
		"is_revoked": false,
		"expires_at": bson.M{"$gt": time.Now().UTC()},
	})
	if err != nil {
		return nil, err
	}
	defer cursor.Close(r.ctx)

	var sessions []sso.UserSession
	if err := cursor.All(r.ctx, &sessions); err != nil {
		return nil, err
	}
	return sessions, nil
}

func (r *MongoUserRepository) GetSessionByToken(accessToken string) (*sso.UserSession, error) {
	var session sso.UserSession
	err := r.sessions.FindOne(r.ctx, bson.M{
		"access_token": accessToken,
		"is_revoked":   false,
		"expires_at":   bson.M{"$gt": time.Now().UTC()},
	}).Decode(&session)
	if err == mongo.ErrNoDocuments {
		return nil, fmt.Errorf("session not found")
	}
	return &session, err
}

func (r *MongoUserRepository) UpdateSessionLastUsed(sessionID string) error {
	_, err := r.sessions.UpdateOne(r.ctx,
		bson.M{"_id": sessionID},
		bson.M{"$set": bson.M{"last_used_at": time.Now().UTC()}},
	)
	return err
}

func (r *MongoUserRepository) RevokeSession(sessionID string) error {
	_, err := r.sessions.UpdateOne(r.ctx,
		bson.M{"_id": sessionID},
		bson.M{"$set": bson.M{"is_revoked": true}},
	)
	return err
}

func (r *MongoUserRepository) DeleteExpiredSessions(userID string) error {
	_, err := r.sessions.DeleteMany(r.ctx, bson.M{
		"user_id": userID,
		"$or": []bson.M{
			{"expires_at": bson.M{"$lt": time.Now().UTC()}},
			{"is_revoked": true},
		},
	})
	return err
}

func (r *MongoUserRepository) Close() error {
	r.cancelFunc()
	return r.db.Client().Disconnect(r.ctx)
}
