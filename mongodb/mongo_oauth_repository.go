package mongodb

import (
	"context"
	"errors"
	"fmt"
	"time"

	ssso "github.com/pilab-dev/shadow-sso"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type OAuthRepository struct {
	db         *mongo.Database
	clients    *mongo.Collection
	authCodes  *mongo.Collection
	tokens     *mongo.Collection
	challenges *mongo.Collection
	sessions   *mongo.Collection // New collection for user sessions
}

func NewOAuthRepository(ctx context.Context, db *mongo.Database) (ssso.OAuthRepository, error) {
	repo := &OAuthRepository{
		db:         db,
		clients:    db.Collection("oauth_clients"),
		authCodes:  db.Collection("auth_codes"),
		tokens:     db.Collection("tokens"),
		challenges: db.Collection("pkce_challenges"),
		sessions:   db.Collection("user_sessions"), // Initialize sessions collection
	}

	if err := repo.createIndexes(ctx); err != nil {
		return nil, err
	}

	return repo, nil
}

func (r *OAuthRepository) createIndexes(ctx context.Context) error {
	// Client indexes
	_, err := r.clients.Indexes().CreateMany(ctx, []mongo.IndexModel{
		{
			Keys:    bson.D{{Key: "client_id", Value: 1}},
			Options: options.Index().SetUnique(true),
		},
	})
	if err != nil {
		return err
	}

	// Auth code indexes
	_, err = r.authCodes.Indexes().CreateMany(ctx, []mongo.IndexModel{
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
	_, err = r.tokens.Indexes().CreateMany(ctx, []mongo.IndexModel{
		{
			Keys:    bson.D{{Key: "token_value", Value: 1}},
			Options: options.Index().SetUnique(true),
		},
		{
			Keys:    bson.D{{Key: "expires_at", Value: 1}},
			Options: options.Index().SetExpireAfterSeconds(0),
		},
		{
			Keys: bson.D{{Key: "user_id", Value: 1}},
		},
		{
			Keys: bson.D{{Key: "client_id", Value: 1}},
		},
	})
	if err != nil {
		return err
	}

	// PKCE challenge indexes
	_, err = r.challenges.Indexes().CreateMany(ctx, []mongo.IndexModel{
		{
			Keys:    bson.D{{Key: "code", Value: 1}},
			Options: options.Index().SetUnique(true),
		},
		{
			Keys:    bson.D{{Key: "created_at", Value: 1}},
			Options: options.Index().SetExpireAfterSeconds(600), // 10 minutes
		},
	})
	if err != nil {
		return err
	}

	// Session indexes
	_, err = r.sessions.Indexes().CreateMany(ctx, []mongo.IndexModel{
		{
			Keys:    bson.D{{Key: "session_id", Value: 1}},
			Options: options.Index().SetUnique(true),
		},
		{
			Keys: bson.D{{Key: "user_id", Value: 1}},
		},
		{
			Keys:    bson.D{{Key: "expires_at", Value: 1}},
			Options: options.Index().SetExpireAfterSeconds(0),
		},
		{
			Keys:    bson.D{{Key: "access_token_hash", Value: 1}},
			Options: options.Index().SetSparse(true).SetUnique(true),
		},
		{
			Keys:    bson.D{{Key: "refresh_token_hash", Value: 1}},
			Options: options.Index().SetSparse(true).SetUnique(true),
		},
	})
	return err
}

// Client operations
func (r *OAuthRepository) CreateClient(ctx context.Context, client *ssso.Client) error {
	_, err := r.clients.InsertOne(ctx, client)
	return err
}

func (r *OAuthRepository) GetClient(ctx context.Context, clientID string) (*ssso.Client, error) {
	var client ssso.Client
	err := r.clients.FindOne(ctx, bson.M{"client_id": clientID}).Decode(&client)
	if err == mongo.ErrNoDocuments {
		return nil, fmt.Errorf("client not found")
	}
	return &client, err
}

func (r *OAuthRepository) ValidateClient(ctx context.Context, clientID, clientSecret string) error {
	var client ssso.Client
	err := r.clients.FindOne(ctx, bson.M{
		"client_id": clientID,
		"secret":    clientSecret,
	}).Decode(&client)
	if err == mongo.ErrNoDocuments {
		return fmt.Errorf("invalid client credentials")
	}
	return err
}

// Auth code operations
func (r *OAuthRepository) SaveAuthCode(ctx context.Context, code *ssso.AuthCode) error {
	_, err := r.authCodes.InsertOne(ctx, code)
	return err
}

func (r *OAuthRepository) GetAuthCode(ctx context.Context, code string) (*ssso.AuthCode, error) {
	var authCode ssso.AuthCode
	err := r.authCodes.FindOne(ctx, bson.M{"code": code}).Decode(&authCode)
	if err == mongo.ErrNoDocuments {
		return nil, fmt.Errorf("auth code not found")
	}
	return &authCode, err
}

func (r *OAuthRepository) MarkAuthCodeAsUsed(ctx context.Context, code string) error {
	_, err := r.authCodes.UpdateOne(ctx,
		bson.M{"code": code},
		bson.M{"$set": bson.M{"used": true}},
	)
	return err
}

// Token operations
func (r *OAuthRepository) StoreToken(ctx context.Context, token *ssso.Token) error {
	_, err := r.tokens.InsertOne(ctx, token)
	return err
}

func (r *OAuthRepository) GetAccessToken(ctx context.Context, tokenValue string) (*ssso.Token, error) {
	var token ssso.Token
	err := r.tokens.FindOne(ctx, bson.M{
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

func (r *OAuthRepository) RevokeToken(ctx context.Context, tokenValue string) error {
	_, err := r.tokens.UpdateOne(ctx,
		bson.M{"token_value": tokenValue},
		bson.M{"$set": bson.M{"is_revoked": true}},
	)
	return err
}

// PKCE operations
func (r *OAuthRepository) SaveCodeChallenge(ctx context.Context, code, challenge string) error {
	_, err := r.challenges.InsertOne(ctx, bson.M{
		"code":       code,
		"challenge":  challenge,
		"created_at": time.Now().UTC(),
	})
	return err
}

func (r *OAuthRepository) GetCodeChallenge(ctx context.Context, code string) (string, error) {
	var result struct {
		Challenge string `bson:"challenge"`
	}
	err := r.challenges.FindOne(ctx, bson.M{"code": code}).Decode(&result)
	if err == mongo.ErrNoDocuments {
		return "", fmt.Errorf("challenge not found")
	}

	return result.Challenge, err
}

func (r *OAuthRepository) DeleteCodeChallenge(ctx context.Context, code string) error {
	_, err := r.challenges.DeleteOne(ctx, bson.M{"code": code})

	return err
}

// Session operations
func (r *OAuthRepository) CreateSession(ctx context.Context, userID string, session *ssso.UserSession) error {
	session.CreatedAt = time.Now().UTC()

	type userSessionStruct struct {
		ssso.UserSession `bson:",inline"`
		AccessTokenHash  string `bson:"access_token_hash"`
		RefreshTokenHash string `bson:"refresh_token_hash"`
	}

	session.UserID = userID

	// Store hashes of access and refresh tokens, as well as the session. This
	// makes it easier to find sessions by token.
	sess := userSessionStruct{
		UserSession:      *session,
		AccessTokenHash:  ssso.HashToken(session.AccessToken),
		RefreshTokenHash: ssso.HashToken(session.RefreshToken),
	}

	_, err := r.sessions.InsertOne(ctx, sess)
	return err
}

// DeleteClient implements ssso.OAuthRepository.
func (r *OAuthRepository) DeleteClient(ctx context.Context, clientID string) error {
	_, err := r.clients.DeleteOne(ctx, bson.M{"client_id": clientID})
	return err
}

// DeleteExpiredAuthCodes implements ssso.OAuthRepository.
func (r *OAuthRepository) DeleteExpiredAuthCodes(ctx context.Context) error {
	_, err := r.authCodes.DeleteMany(ctx, bson.M{"expires_at": bson.M{"$lt": time.Now().UTC()}})

	return err
}

// DeleteExpiredSessions implements ssso.OAuthRepository.
func (r *OAuthRepository) DeleteExpiredSessions(ctx context.Context, userID string) error {
	_, err := r.sessions.DeleteMany(ctx, bson.M{"user_id": userID, "expires_at": bson.M{"$lt": time.Now().UTC()}})

	return err
}

// DeleteExpiredTokens implements ssso.OAuthRepository.
func (r *OAuthRepository) DeleteExpiredTokens(ctx context.Context) error {
	_, err := r.tokens.DeleteMany(ctx, bson.M{"expires_at": bson.M{"$lt": time.Now().UTC()}})

	return err
}

// GetAccessTokenInfo implements ssso.OAuthRepository.
func (r *OAuthRepository) GetAccessTokenInfo(ctx context.Context, tokenValue string) (*ssso.TokenInfo, error) {
	var token ssso.Token
	err := r.tokens.FindOne(ctx, bson.M{
		"token_value": tokenValue,
		"token_type":  "access_token",
		"is_revoked":  false,
		"expires_at":  bson.M{"$gt": time.Now().UTC()},
	}).Decode(&token)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, fmt.Errorf("access token not found or expired")
		}
		return nil, err
	}

	return &ssso.TokenInfo{
		ClientID:  token.ClientID,
		UserID:    token.UserID,
		Scope:     token.Scope,
		ExpiresAt: token.ExpiresAt,
	}, nil
}

// GetRefreshToken implements ssso.OAuthRepository.
func (r *OAuthRepository) GetRefreshToken(ctx context.Context, tokenValue string) (*ssso.Token, error) {
	var token ssso.Token
	err := r.tokens.FindOne(ctx, bson.M{
		"token_value": tokenValue,
		"token_type":  "refresh_token",
		"is_revoked":  false,
		"expires_at":  bson.M{"$gt": time.Now().UTC()},
	}).Decode(&token)

	if err == mongo.ErrNoDocuments {
		return nil, fmt.Errorf("refresh token not found")
	}

	return &token, err
}

// GetRefreshTokenInfo implements ssso.OAuthRepository.
func (r *OAuthRepository) GetRefreshTokenInfo(ctx context.Context, tokenValue string) (*ssso.TokenInfo, error) {
	var token ssso.Token
	err := r.tokens.FindOne(ctx, bson.M{
		"token_value": tokenValue,
		"token_type":  "refresh_token",
		"is_revoked":  false,
		"expires_at":  bson.M{"$gt": time.Now().UTC()},
	}).Decode(&token)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, fmt.Errorf("refresh token not found or expired")
		}
		return nil, err
	}

	return &ssso.TokenInfo{
		ClientID:  token.ClientID,
		UserID:    token.UserID,
		Scope:     token.Scope,
		ExpiresAt: token.ExpiresAt,
	}, nil
}

// GetSessionByToken implements ssso.OAuthRepository.
func (r *OAuthRepository) GetSessionByToken(ctx context.Context, token string) (*ssso.UserSession, error) {
	var session ssso.UserSession
	err := r.sessions.FindOne(ctx, bson.M{
		"$or": []bson.M{
			{"access_token_hash": ssso.HashToken(token)},
			{"refresh_token_hash": ssso.HashToken(token)},
		},
		"expires_at": bson.M{"$gt": time.Now().UTC()},
	}).Decode(&session)
	if err == mongo.ErrNoDocuments {
		return nil, fmt.Errorf("session not found")
	}

	return &session, err
}

// GetTokenInfo implements ssso.OAuthRepository.
func (r *OAuthRepository) GetTokenInfo(ctx context.Context, tokenValue string) (*ssso.Token, error) {
	var token ssso.Token
	err := r.tokens.FindOne(ctx, bson.M{
		"token_value": tokenValue,
		"expires_at":  bson.M{"$gt": time.Now().UTC()},
		"is_revoked":  false,
	}).Decode(&token)
	if err == mongo.ErrNoDocuments {
		return nil, fmt.Errorf("token not found or expired")
	}
	return &token, err
}

// GetUserSessions implements ssso.OAuthRepository.
func (r *OAuthRepository) GetUserSessions(ctx context.Context, userID string) ([]ssso.UserSession, error) {
	var sessions []ssso.UserSession
	cursor, err := r.sessions.Find(ctx, bson.M{"user_id": userID, "expires_at": bson.M{"$gt": time.Now().UTC()}})
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)
	if err := cursor.All(ctx, &sessions); err != nil {
		return nil, err
	}

	return sessions, nil
}

// RevokeAllClientTokens implements ssso.OAuthRepository.
func (r *OAuthRepository) RevokeAllClientTokens(ctx context.Context, clientID string) error {
	_, err := r.tokens.UpdateMany(ctx, bson.M{"client_id": clientID}, bson.M{"$set": bson.M{"is_revoked": true}})
	return err
}

// RevokeAllUserTokens implements ssso.OAuthRepository.
func (r *OAuthRepository) RevokeAllUserTokens(ctx context.Context, userID string) error {
	_, err := r.tokens.UpdateMany(ctx, bson.M{"user_id": userID}, bson.M{"$set": bson.M{"is_revoked": true}})
	return err
}

// RevokeRefreshToken implements ssso.OAuthRepository.
func (r *OAuthRepository) RevokeRefreshToken(ctx context.Context, tokenValue string) error {
	_, err := r.tokens.UpdateOne(ctx,
		bson.M{"token_value": tokenValue, "token_type": "refresh_token"},
		bson.M{"$set": bson.M{"is_revoked": true}},
	)

	return err
}

// RevokeSession implements ssso.OAuthRepository.
func (r *OAuthRepository) RevokeSession(ctx context.Context, sessionID string) error {
	_, err := r.sessions.DeleteOne(ctx, bson.M{"session_id": sessionID})

	return err
}

// UpdateClient implements ssso.OAuthRepository.
func (r *OAuthRepository) UpdateClient(ctx context.Context, client *ssso.Client) error {
	_, err := r.clients.UpdateOne(ctx, bson.M{"client_id": client.ID}, bson.M{"$set": client})
	return err
}

// UpdateSessionLastUsed implements ssso.OAuthRepository.
func (r *OAuthRepository) UpdateSessionLastUsed(ctx context.Context, sessionID string) error {
	_, err := r.sessions.UpdateOne(ctx,
		bson.M{"session_id": sessionID},
		bson.M{"$set": bson.M{"last_used": time.Now().UTC()}},
	)
	return err
}

// ValidateAccessToken implements ssso.OAuthRepository.
func (r *OAuthRepository) ValidateAccessToken(ctx context.Context, token string) (string, error) {
	var t ssso.Token
	err := r.tokens.FindOne(ctx, bson.M{
		"token_value": token,
		"token_type":  "access_token",
		"is_revoked":  false,
		"expires_at":  bson.M{"$gt": time.Now().UTC()},
	}).Decode(&t)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return "", fmt.Errorf("invalid access token")
		}
		return "", err
	}
	return t.UserID, nil
}

func (r *OAuthRepository) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	return r.db.Client().Disconnect(ctx)
}
