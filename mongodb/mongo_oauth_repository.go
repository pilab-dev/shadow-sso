//go:build mongodb

// Package mongodb implements the OAuthRepository interface using MongoDB.
// To use this package, you need to enable the "mongodb" build tag.
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

type MongoOAuthRepository struct {
	db         *mongo.Database
	clients    *mongo.Collection
	authCodes  *mongo.Collection
	tokens     *mongo.Collection
	challenges *mongo.Collection
	ctx        context.Context
	cancelFunc context.CancelFunc
}

func NewMongoOAuthRepository(uri string, dbName string) (*MongoOAuthRepository, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	client, err := mongo.Connect(ctx, options.Client().ApplyURI(uri))
	if err != nil {
		cancel()
		return nil, fmt.Errorf("failed to connect to MongoDB: %w", err)
	}

	db := client.Database(dbName)
	repo := &MongoOAuthRepository{
		db:         db,
		clients:    db.Collection("oauth_clients"),
		authCodes:  db.Collection("auth_codes"),
		tokens:     db.Collection("tokens"),
		challenges: db.Collection("pkce_challenges"),
		ctx:        ctx,
		cancelFunc: cancel,
	}

	if err := repo.createIndexes(); err != nil {
		cancel()
		return nil, err
	}

	return repo, nil
}

func (r *MongoOAuthRepository) createIndexes() error {
	// Client indexes
	_, err := r.clients.Indexes().CreateMany(r.ctx, []mongo.IndexModel{
		{
			Keys:    bson.D{{Key: "client_id", Value: 1}},
			Options: options.Index().SetUnique(true),
		},
	})
	if err != nil {
		return err
	}

	// Auth code indexes
	_, err = r.authCodes.Indexes().CreateMany(r.ctx, []mongo.IndexModel{
		{
			Keys:    bson.D{{Key: "code", Value: 1}},
			Options: options.Index().SetUnique(true),
		},
		{
			Keys:    bson.D{{Key: "expires_at", Value: 1}},
			Options: options.Index().SetExpireAfterSeconds(0),
		},
	})
	if err != nil {
		return err
	}

	// Token indexes
	_, err = r.tokens.Indexes().CreateMany(r.ctx, []mongo.IndexModel{
		{
			Keys:    bson.D{{Key: "token_value", Value: 1}},
			Options: options.Index().SetUnique(true),
		},
		{
			Keys:    bson.D{{Key: "expires_at", Value: 1}},
			Options: options.Index().SetExpireAfterSeconds(0),
		},
	})
	if err != nil {
		return err
	}

	// PKCE challenge indexes
	_, err = r.challenges.Indexes().CreateMany(r.ctx, []mongo.IndexModel{
		{
			Keys:    bson.D{{Key: "code", Value: 1}},
			Options: options.Index().SetUnique(true),
		},
		{
			Keys:    bson.D{{Key: "created_at", Value: 1}},
			Options: options.Index().SetExpireAfterSeconds(600), // 10 minutes
		},
	})
	return err
}

// Client operations
func (r *MongoOAuthRepository) CreateClient(client *ssso.Client) error {
	_, err := r.clients.InsertOne(r.ctx, client)
	return err
}

func (r *MongoOAuthRepository) GetClient(clientID string) (*ssso.Client, error) {
	var client ssso.Client
	err := r.clients.FindOne(r.ctx, bson.M{"client_id": clientID}).Decode(&client)
	if err == mongo.ErrNoDocuments {
		return nil, fmt.Errorf("client not found")
	}
	return &client, err
}

func (r *MongoOAuthRepository) ValidateClient(clientID, clientSecret string) error {
	var client ssso.Client
	err := r.clients.FindOne(r.ctx, bson.M{
		"client_id": clientID,
		"secret":    clientSecret,
	}).Decode(&client)
	if err == mongo.ErrNoDocuments {
		return fmt.Errorf("invalid client credentials")
	}
	return err
}

// Auth code operations
func (r *MongoOAuthRepository) SaveAuthCode(code *ssso.AuthCode) error {
	_, err := r.authCodes.InsertOne(r.ctx, code)
	return err
}

func (r *MongoOAuthRepository) GetAuthCode(code string) (*ssso.AuthCode, error) {
	var authCode ssso.AuthCode
	err := r.authCodes.FindOne(r.ctx, bson.M{"code": code}).Decode(&authCode)
	if err == mongo.ErrNoDocuments {
		return nil, fmt.Errorf("auth code not found")
	}
	return &authCode, err
}

func (r *MongoOAuthRepository) MarkAuthCodeAsUsed(code string) error {
	_, err := r.authCodes.UpdateOne(r.ctx,
		bson.M{"code": code},
		bson.M{"$set": bson.M{"used": true}},
	)
	return err
}

// Token operations
func (r *MongoOAuthRepository) StoreToken(token *ssso.Token) error {
	_, err := r.tokens.InsertOne(r.ctx, token)
	return err
}

func (r *MongoOAuthRepository) GetAccessToken(tokenValue string) (*ssso.Token, error) {
	var token ssso.Token
	err := r.tokens.FindOne(r.ctx, bson.M{
		"token_value": tokenValue,
		"token_type":  "access_token",
		"is_revoked":  false,
		"expires_at":  bson.M{"$gt": time.Now().UTC()},
	}).Decode(&token)
	if err == mongo.ErrNoDocuments {
		return nil, fmt.Errorf("token not found")
	}
	return &token, err
}

func (r *MongoOAuthRepository) RevokeToken(tokenValue string) error {
	_, err := r.tokens.UpdateOne(r.ctx,
		bson.M{"token_value": tokenValue},
		bson.M{"$set": bson.M{"is_revoked": true}},
	)
	return err
}

// PKCE operations
func (r *MongoOAuthRepository) SaveCodeChallenge(code, challenge string) error {
	_, err := r.challenges.InsertOne(r.ctx, bson.M{
		"code":       code,
		"challenge":  challenge,
		"created_at": time.Now().UTC(),
	})
	return err
}

func (r *MongoOAuthRepository) GetCodeChallenge(code string) (string, error) {
	var result struct {
		Challenge string `bson:"challenge"`
	}
	err := r.challenges.FindOne(r.ctx, bson.M{"code": code}).Decode(&result)
	if err == mongo.ErrNoDocuments {
		return "", fmt.Errorf("challenge not found")
	}
	return result.Challenge, err
}

func (r *MongoOAuthRepository) DeleteCodeChallenge(code string) error {
	_, err := r.challenges.DeleteOne(r.ctx, bson.M{"code": code})
	return err
}

func (r *MongoOAuthRepository) Close() error {
	r.cancelFunc()
	return r.db.Client().Disconnect(r.ctx)
}
