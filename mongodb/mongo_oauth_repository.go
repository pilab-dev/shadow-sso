package mongodb

import (
	"context"
	"errors"
	"fmt"
	"time"

	ssso "github.com/pilab-dev/shadow-sso"
	"github.com/pilab-dev/shadow-sso/cache"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
	"github.com/google/uuid"
)

type OAuthRepository struct {
	db         *mongo.Database
	clients    *mongo.Collection
	authCodes  *mongo.Collection
	tokens     *mongo.Collection
	challenges *mongo.Collection
	sessions   *mongo.Collection // New collection for user sessions
}

//nolint:ireturn,varnamelen
func NewOAuthRepository(ctx context.Context, db *mongo.Database) (ssso.OAuthRepository, error) {
	repo := &OAuthRepository{
		db:         db,
		clients:    db.Collection(ClientsCollection),
		authCodes:  db.Collection(CodesCollection),
		tokens:     db.Collection(TokensCollection),
		challenges: db.Collection(ChallengesCollection),
		sessions:   db.Collection(UserSessionsCollection), // Initialize sessions collection
	}

	if err := repo.createIndexes(ctx); err != nil {
		return nil, err
	}

	return repo, nil
}

//nolint:funlen
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
		//nolint:exhaustruct
		{
			Keys: bson.D{{Key: "user_id", Value: 1}},
		},
		//nolint:exhaustruct
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
	//nolint:exhaustruct
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

// CreateClient creates a new OAuth2 client and inserts it into the database.
func (r *OAuthRepository) CreateClient(ctx context.Context, client *ssso.Client) error {
	_, err := r.clients.InsertOne(ctx, client)
	return err
}

func (r *OAuthRepository) GetClient(ctx context.Context, clientID string) (*ssso.Client, error) {
	var client ssso.Client
	err := r.clients.FindOne(ctx, bson.M{"client_id": clientID}).Decode(&client)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return nil, fmt.Errorf("client not found: %w", err)
	}
	return &client, err
}

func (r *OAuthRepository) ValidateClient(ctx context.Context, clientID, clientSecret string) error {
	var client ssso.Client
	err := r.clients.FindOne(ctx, bson.M{
		"client_id": clientID,
		"secret":    clientSecret,
	}).Decode(&client)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return fmt.Errorf("invalid client credentials: %w", err)
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
	if errors.Is(err, mongo.ErrNoDocuments) {
		return nil, fmt.Errorf("auth code not found: %w", err)
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

// StoreToken saves a new access or refresh token in the repository.
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
	if errors.Is(err, mongo.ErrNoDocuments) {
		return nil, fmt.Errorf("token not found: %w", err)
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
	if errors.Is(err, mongo.ErrNoDocuments) {
		return "", fmt.Errorf("challenge not found: %w", err)
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
		AccessTokenHash:  cache.HashToken(session.AccessToken),
		RefreshTokenHash: cache.HashToken(session.RefreshToken),
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
//
//nolint:dupl
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
			return nil, fmt.Errorf("access token not found or expired: %w", err)
		}
		return nil, err
	}

	return &ssso.TokenInfo{
		ID:        token.ID,
		TokenType: token.TokenType,
		ClientID:  token.ClientID,
		UserID:    token.UserID,
		Scope:     token.Scope,
		IssuedAt:  token.CreatedAt,
		ExpiresAt: token.ExpiresAt,
		IsRevoked: token.IsRevoked,
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

	if errors.Is(err, mongo.ErrNoDocuments) {
		return nil, fmt.Errorf("refresh token not found: %w", err)
	}

	return &token, err
}

// GetRefreshTokenInfo implements ssso.OAuthRepository.
//
//nolint:dupl
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
			return nil, fmt.Errorf("refresh token not found or expired: %w", err)
		}
		return nil, err
	}

	return &ssso.TokenInfo{
		ID:        token.ID,
		TokenType: token.TokenType,
		ClientID:  token.ClientID,
		UserID:    token.UserID,
		Scope:     token.Scope,
		IssuedAt:  token.CreatedAt,
		ExpiresAt: token.ExpiresAt,
		IsRevoked: token.IsRevoked,
	}, nil
}

// GetSessionByToken implements ssso.OAuthRepository.
func (r *OAuthRepository) GetSessionByToken(ctx context.Context, token string) (*ssso.UserSession, error) {
	var session ssso.UserSession
	err := r.sessions.FindOne(ctx, bson.M{
		"$or": []bson.M{
			{"access_token_hash": cache.HashToken(token)},
			{"refresh_token_hash": cache.HashToken(token)},
		},
		"expires_at": bson.M{"$gt": time.Now().UTC()},
	}).Decode(&session)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return nil, fmt.Errorf("session not found: %w", err)
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
	if errors.Is(err, mongo.ErrNoDocuments) {
		return nil, fmt.Errorf("token not found or expired: %w", err)
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
func (r *OAuthRepository) ValidateAccessToken(ctx context.Context, tokenValue string) (string, error) {
	var token ssso.Token

	err := r.tokens.FindOne(ctx, bson.M{
		"token_value": tokenValue, // ! TODO: investigate the option to change and store it as hash, for better perofrmance
		"token_type":  "access_token",
		"is_revoked":  false,
		"expires_at":  bson.M{"$gt": time.Now().UTC()},
	}).Decode(&token)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return "", fmt.Errorf("invalid access token: %w", err)
		}
		return "", err
	}
	return token.UserID, nil
}

func (r *OAuthRepository) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	return r.db.Client().Disconnect(ctx)
}

// DeviceAuthorizationRepository implementation

// SaveDeviceAuth stores a new device authorization request.
func (r *OAuthRepository) SaveDeviceAuth(ctx context.Context, auth *ssso.DeviceCode) error {
	collection := r.db.Collection(deviceAuthCollectionName)
	auth.ID = uuid.NewString()
	auth.CreatedAt = time.Now().UTC()
	_, err := collection.InsertOne(ctx, auth)
	if err != nil {
		// Handle potential duplicate key errors if UserCode or DeviceCode should be unique globally
		// if mongo.IsDuplicateKeyError(err) { ... } // Note: mongo.IsDuplicateKeyError is for older driver versions. v2 uses a different approach.
		// For v2, you might check for err.HasErrorCode(11000) or err.HasErrorLabel("DuplicateKey")
		return err
	}
	return nil
}

// GetDeviceAuthByDeviceCode retrieves a device authorization record by its device_code.
func (r *OAuthRepository) GetDeviceAuthByDeviceCode(ctx context.Context, deviceCode string) (*ssso.DeviceCode, error) {
	collection := r.db.Collection(deviceAuthCollectionName)
	var result ssso.DeviceCode
	err := collection.FindOne(ctx, bson.M{"device_code": deviceCode}).Decode(&result)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, ssso.ErrDeviceCodeNotFound // Define this error in ssso package
		}
		return nil, err
	}
	return &result, nil
}

// GetDeviceAuthByUserCode retrieves a device authorization record by its user_code.
func (r *OAuthRepository) GetDeviceAuthByUserCode(ctx context.Context, userCode string) (*ssso.DeviceCode, error) {
	collection := r.db.Collection(deviceAuthCollectionName)
	var result ssso.DeviceCode
	filter := bson.M{
		"user_code":  userCode,
		"expires_at": bson.M{"$gt": time.Now().UTC()},
		// "status": ssso.DeviceCodeStatusPending, // Add this if direct lookups should only find pending codes
	}
	err := collection.FindOne(ctx, filter).Decode(&result)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, ssso.ErrUserCodeNotFound // Define this error in ssso package
		}
		return nil, err
	}
	return &result, nil
}

// ApproveDeviceAuth marks a device authorization as approved by a user.
func (r *OAuthRepository) ApproveDeviceAuth(ctx context.Context, userCode string, userID string) (*ssso.DeviceCode, error) {
	collection := r.db.Collection(deviceAuthCollectionName)
	filter := bson.M{
		"user_code":  userCode,
		"expires_at": bson.M{"$gt": time.Now().UTC()},
		"status":     ssso.DeviceCodeStatusPending,
	}
	update := bson.M{
		"$set": bson.M{
			"status":  ssso.DeviceCodeStatusAuthorized,
			"user_id": userID,
		},
	}
	opt := options.FindOneAndUpdate().SetReturnDocument(options.After)
	var updatedDoc ssso.DeviceCode
	err := collection.FindOneAndUpdate(ctx, filter, update, opt).Decode(&updatedDoc)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			// Could be expired, already approved, or code never existed
			return nil, ssso.ErrCannotApproveDeviceAuth // Define this error
		}
		return nil, err
	}
	return &updatedDoc, nil
}

// UpdateDeviceAuthStatus updates the status of a device authorization record.
func (r *OAuthRepository) UpdateDeviceAuthStatus(ctx context.Context, deviceCode string, status ssso.DeviceCodeStatus) error {
	collection := r.db.Collection(deviceAuthCollectionName)
	filter := bson.M{"device_code": deviceCode}
	update := bson.M{"$set": bson.M{"status": status}}
	result, err := collection.UpdateOne(ctx, filter, update)
	if err != nil {
		return err
	}
	if result.MatchedCount == 0 {
		return ssso.ErrDeviceCodeNotFound // Use a defined error
	}
	return nil
}

// UpdateDeviceAuthLastPolledAt updates the last polled timestamp for a device code.
func (r *OAuthRepository) UpdateDeviceAuthLastPolledAt(ctx context.Context, deviceCode string) error {
	collection := r.db.Collection(deviceAuthCollectionName)
	filter := bson.M{"device_code": deviceCode}
	update := bson.M{"$set": bson.M{"last_polled_at": time.Now().UTC()}}
	result, err := collection.UpdateOne(ctx, filter, update)
	if err != nil {
		return err
	}
	if result.MatchedCount == 0 {
		return ssso.ErrDeviceCodeNotFound
	}
	return nil
}

// DeleteExpiredDeviceAuths removes device authorization records that have expired.
func (r *OAuthRepository) DeleteExpiredDeviceAuths(ctx context.Context) error {
	collection := r.db.Collection(deviceAuthCollectionName)
	filter := bson.M{
		"$or": []bson.M{
			{"expires_at": bson.M{"$lte": time.Now().UTC()}},
			// Could also delete already redeemed and old codes
			// {"status": ssso.DeviceCodeStatusRedeemed, "created_at": bson.M{"$lt": time.Now().Add(-someOldDuration)}},
		},
	}
	_, err := collection.DeleteMany(ctx, filter)
	return err
}
