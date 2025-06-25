package mongodb

import (
	"context"
	"errors"
	"fmt"
	"strconv" // For ListClients
	"time"

	"github.com/google/uuid"
	"github.com/pilab-dev/shadow-sso/client" // Import the canonical client model
	"github.com/pilab-dev/shadow-sso/domain" // Added domain import
	serrors "github.com/pilab-dev/shadow-sso/errors" // Added for serrors
	"github.com/rs/zerolog/log"              // Assuming logger usage
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

// OAuthRepository struct definition remains the same, fields are collection pointers
type OAuthRepository struct {
	db         *mongo.Database
	clients    *mongo.Collection
	authCodes  *mongo.Collection
	tokens     *mongo.Collection
	challenges *mongo.Collection
	sessions   *mongo.Collection
}

// NewOAuthRepository constructor returns the domain.OAuthRepository interface
func NewOAuthRepository(ctx context.Context, db *mongo.Database) (domain.OAuthRepository, error) {
	repo := &OAuthRepository{
		db:         db,
		clients:    db.Collection(ClientsCollection),
		authCodes:  db.Collection(CodesCollection),
		tokens:     db.Collection(TokensCollection),
		challenges: db.Collection(ChallengesCollection),
		sessions:   db.Collection(UserSessionsCollection),
	}

	if err := repo.createIndexes(ctx); err != nil {
		return nil, err
	}

	return repo, nil
}

func (r *OAuthRepository) createIndexes(ctx context.Context) error {
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

// --- Client Methods (using *client.Client) ---

func (r *OAuthRepository) CreateClient(ctx context.Context, c *client.Client) error {
	if c.ID == "" {
		return errors.New("client ID is required")
	}
	c.CreatedAt = time.Now().UTC()
	c.UpdatedAt = time.Now().UTC()
	_, err := r.clients.InsertOne(ctx, c)
	if err != nil {
		var writeException mongo.WriteException
		if errors.As(err, &writeException) {
			for _, writeError := range writeException.WriteErrors {
				if writeError.Code == 11000 || writeError.Code == 11001 {
					return errors.New("client with this client_id already exists")
				}
			}
		}
		log.Error().Err(err).Msg("Error creating client in MongoDB")
		return err
	}
	return nil
}

func (r *OAuthRepository) GetClient(ctx context.Context, clientID string) (*client.Client, error) {
	var c client.Client
	err := r.clients.FindOne(ctx, bson.M{"client_id": clientID}).Decode(&c)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, errors.New("client not found")
		}
		log.Error().Err(err).Str("clientID", clientID).Msg("Error getting client by ID from MongoDB")
		return nil, err
	}
	return &c, nil
}

func (r *OAuthRepository) UpdateClient(ctx context.Context, c *client.Client) error {
	if c.ID == "" {
		return errors.New("client ID is required for update")
	}
	c.UpdatedAt = time.Now().UTC()
	result, err := r.clients.ReplaceOne(ctx, bson.M{"client_id": c.ID}, c)
	if err != nil {
		log.Error().Err(err).Str("clientID", c.ID).Msg("Error updating client in MongoDB")
		return err
	}
	if result.MatchedCount == 0 {
		return errors.New("client not found for update")
	}
	return nil
}

func (r *OAuthRepository) DeleteClient(ctx context.Context, clientID string) error {
	result, err := r.clients.DeleteOne(ctx, bson.M{"client_id": clientID})
	if err != nil {
		log.Error().Err(err).Str("clientID", clientID).Msg("Error deleting client from MongoDB")
		return err
	}
	if result.DeletedCount == 0 {
		return errors.New("client not found for deletion")
	}
	return nil
}

func (r *OAuthRepository) ListClients(ctx context.Context, pageSize int32, pageToken string) ([]*client.Client, string, error) {
	if pageSize <= 0 {
		pageSize = 10
	}
	if pageSize > 100 {
		pageSize = 100
	}
	skip := int64(0)
	if pageToken != "" {
		parsedSkip, _ := strconv.ParseInt(pageToken, 10, 64)
		if parsedSkip > 0 {
			skip = parsedSkip
		}
	}

	findOptions := options.Find().SetSkip(skip).SetLimit(int64(pageSize)).SetSort(bson.D{{"client_name", 1}})
	cursor, err := r.clients.Find(ctx, bson.M{}, findOptions)
	if err != nil {
		log.Error().Err(err).Msg("Error listing clients from MongoDB")
		return nil, "", err
	}
	defer cursor.Close(ctx)

	var clients []*client.Client
	if err = cursor.All(ctx, &clients); err != nil {
		log.Error().Err(err).Msg("Error decoding listed clients from MongoDB")
		return nil, "", err
	}
	nextPageTokenVal := ""
	if int32(len(clients)) == pageSize {
		nextPageTokenVal = strconv.FormatInt(skip+int64(pageSize), 10)
	}
	return clients, nextPageTokenVal, nil
}

func (r *OAuthRepository) ValidateClient(ctx context.Context, clientID, clientSecret string) error {
	c, err := r.GetClient(ctx, clientID)
	if err != nil {
		return err
	}
	if c.Secret != clientSecret {
		return serrors.ErrInvalidClientCredentials
	}
	if !c.IsActive {
		return errors.New("client is inactive")
	}
	return nil
}

// --- Token Methods (using *domain.Token and *domain.TokenInfo) ---
func (r *OAuthRepository) StoreToken(ctx context.Context, token *domain.Token) error {
	_, err := r.tokens.InsertOne(ctx, token)
	return err
}

func (r *OAuthRepository) GetAccessToken(ctx context.Context, tokenValue string) (*domain.Token, error) {
	var token domain.Token
	err := r.tokens.FindOne(ctx, bson.M{
		"token_value": tokenValue, "token_type": "access_token",
		"is_revoked": false, "expires_at": bson.M{"$gt": time.Now().UTC()},
	}).Decode(&token)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return nil, errors.New("token not found or invalid")
	}
	return &token, err
}

func (r *OAuthRepository) RevokeToken(ctx context.Context, tokenValue string) error {
	_, err := r.tokens.UpdateOne(ctx, bson.M{"token_value": tokenValue, "token_type": "access_token"}, bson.M{"$set": bson.M{"is_revoked": true}})
	return err
}

func (r *OAuthRepository) GetRefreshToken(ctx context.Context, tokenValue string) (*domain.Token, error) {
	var token domain.Token
	err := r.tokens.FindOne(ctx, bson.M{
		"token_value": tokenValue, "token_type": "refresh_token",
		"is_revoked": false, "expires_at": bson.M{"$gt": time.Now().UTC()},
	}).Decode(&token)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return nil, errors.New("refresh token not found or invalid")
	}
	return &token, err
}

func (r *OAuthRepository) GetRefreshTokenInfo(ctx context.Context, tokenValue string) (*domain.TokenInfo, error) {
	token, err := r.GetRefreshToken(ctx, tokenValue)
	if err != nil {
		return nil, err
	}
	return &domain.TokenInfo{ID: token.ID, TokenType: token.TokenType, ClientID: token.ClientID, UserID: token.UserID, Scope: token.Scope, IssuedAt: token.CreatedAt, ExpiresAt: token.ExpiresAt, IsRevoked: token.IsRevoked, Roles: token.Roles}, nil
}

func (r *OAuthRepository) GetAccessTokenInfo(ctx context.Context, tokenValue string) (*domain.TokenInfo, error) {
	token, err := r.GetAccessToken(ctx, tokenValue)
	if err != nil {
		return nil, err
	}
	return &domain.TokenInfo{ID: token.ID, TokenType: token.TokenType, ClientID: token.ClientID, UserID: token.UserID, Scope: token.Scope, IssuedAt: token.CreatedAt, ExpiresAt: token.ExpiresAt, IsRevoked: token.IsRevoked, Roles: token.Roles}, nil
}

func (r *OAuthRepository) RevokeRefreshToken(ctx context.Context, tokenValue string) error {
	filter := bson.M{"token_value": tokenValue, "token_type": "refresh_token"}
	update := bson.M{"$set": bson.M{"is_revoked": true}}
	result, err := r.tokens.UpdateOne(ctx, filter, update)
	if err != nil {
		log.Error().Err(err).Str("refreshToken", tokenValue).Msg("Error revoking refresh token")
		return fmt.Errorf("failed to revoke refresh token: %w", err)
	}
	if result.MatchedCount == 0 {
		log.Warn().Str("refreshToken", tokenValue).Msg("Refresh token not found to revoke, or already revoked and cleaned.")
	} else {
		log.Debug().Str("refreshToken", tokenValue).Msg("Refresh token marked as revoked.")
	}
	return nil
}

func (r *OAuthRepository) RevokeAllUserTokens(ctx context.Context, userID string) error {
	_, err := r.tokens.UpdateMany(ctx, bson.M{"user_id": userID}, bson.M{"$set": bson.M{"is_revoked": true}})
	return err
}

func (r *OAuthRepository) RevokeAllClientTokens(ctx context.Context, clientID string) error {
	_, err := r.tokens.UpdateMany(ctx, bson.M{"client_id": clientID}, bson.M{"$set": bson.M{"is_revoked": true}})
	return err
}

func (r *OAuthRepository) DeleteExpiredTokens(ctx context.Context) error {
	_, err := r.tokens.DeleteMany(ctx, bson.M{"expires_at": bson.M{"$lte": time.Now().UTC()}})
	return err
}

func (r *OAuthRepository) ValidateAccessToken(ctx context.Context, tokenValue string) (string, error) {
	token, err := r.GetAccessToken(ctx, tokenValue)
	if err != nil {
		return "", err
	}
	return token.UserID, nil
}

func (r *OAuthRepository) GetTokenInfo(ctx context.Context, tokenValue string) (*domain.Token, error) {
	var token domain.Token
	err := r.tokens.FindOne(ctx, bson.M{"token_value": tokenValue, "is_revoked": false, "expires_at": bson.M{"$gt": time.Now().UTC()}}).Decode(&token)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return nil, errors.New("token not found or invalid")
	}
	return &token, err
}

// --- Auth Code Methods (using *domain.AuthCode) ---
func (r *OAuthRepository) SaveAuthCode(ctx context.Context, authCode *domain.AuthCode) error {
	if authCode.Code == "" {
		return errors.New("auth code value cannot be empty")
	}
	authCode.CreatedAt = time.Now().UTC()
	_, err := r.authCodes.InsertOne(ctx, authCode)
	if err != nil {
		var writeException mongo.WriteException
		if errors.As(err, &writeException) {
			for _, writeError := range writeException.WriteErrors {
				if writeError.Code == 11000 || writeError.Code == 11001 {
					return fmt.Errorf("authorization code %s already exists: %w", authCode.Code, err)
				}
			}
		}
		log.Error().Err(err).Str("code", authCode.Code).Msg("Error saving authorization code")
		return fmt.Errorf("failed to save authorization code: %w", err)
	}
	log.Debug().Str("code", authCode.Code).Str("userID", authCode.UserID).Msg("Authorization code saved")
	return nil
}

func (r *OAuthRepository) GetAuthCode(ctx context.Context, codeValue string) (*domain.AuthCode, error) {
	var authCode domain.AuthCode
	err := r.authCodes.FindOne(ctx, bson.M{"code": codeValue}).Decode(&authCode)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, fmt.Errorf("authorization code %s not found", codeValue)
		}
		log.Error().Err(err).Str("code", codeValue).Msg("Error retrieving authorization code")
		return nil, fmt.Errorf("failed to retrieve authorization code: %w", err)
	}
	return &authCode, nil
}

func (r *OAuthRepository) MarkAuthCodeAsUsed(ctx context.Context, codeValue string) error {
	filter := bson.M{"code": codeValue}
	update := bson.M{"$set": bson.M{"used": true}}
	result, err := r.authCodes.UpdateOne(ctx, filter, update)
	if err != nil {
		log.Error().Err(err).Str("code", codeValue).Msg("Error marking authorization code as used")
		return fmt.Errorf("failed to mark authorization code as used: %w", err)
	}
	if result.MatchedCount == 0 {
		return fmt.Errorf("authorization code %s not found to mark as used", codeValue)
	}
	log.Debug().Str("code", codeValue).Msg("Authorization code marked as used")
	return nil
}

func (r *OAuthRepository) DeleteExpiredAuthCodes(ctx context.Context) error {
	_, err := r.authCodes.DeleteMany(ctx, bson.M{"expires_at": bson.M{"$lte": time.Now().UTC()}})
	return err
}

// --- PKCE Methods ---
func (r *OAuthRepository) SaveCodeChallenge(ctx context.Context, code string, challenge string) error {
	_, err := r.challenges.InsertOne(ctx, bson.M{"code": code, "challenge": challenge, "created_at": time.Now()})
	if err != nil {
		var writeException mongo.WriteException
		if errors.As(err, &writeException) {
			for _, writeError := range writeException.WriteErrors {
				if writeError.Code == 11000 || writeError.Code == 11001 {
					log.Warn().Str("code", code).Msg("SaveCodeChallenge: challenge for this code already exists.")
					return nil // Treat as non-fatal if already exists
				}
			}
		}
		return err // Return other errors
	}
	return nil
}

func (r *OAuthRepository) GetCodeChallenge(ctx context.Context, code string) (string, error) {
	authCode, err := r.GetAuthCode(ctx, code)
	if err != nil {
		log.Warn().Err(err).Str("auth_code_value", code).Msg("GetCodeChallenge: Failed to retrieve AuthCode to get challenge")
		return "", fmt.Errorf("failed to get auth code '%s' for pkce challenge: %w", code, err)
	}

	if authCode.CodeChallenge == "" {
		log.Warn().Str("auth_code_value", code).Msg("GetCodeChallenge: CodeChallenge field is empty in retrieved AuthCode")
		return "", errors.New("pkce code_challenge not set for the given authorization code")
	}
	return authCode.CodeChallenge, nil
}

func (r *OAuthRepository) DeleteCodeChallenge(ctx context.Context, code string) error {
	log.Debug().Str("code", code).Msg("DeleteCodeChallenge called. If PKCE challenge is part of AuthCode, this might be redundant.")
	result, err := r.challenges.DeleteOne(ctx, bson.M{"code": code})
	if err != nil {
		return err
	}
	if result.DeletedCount == 0 { // Changed from MatchedCount to DeletedCount
		log.Warn().Str("code", code).Msg("No document found in 'challenges' collection to delete for code.")
	}
	return nil
}

// Close method
func (r *OAuthRepository) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return r.db.Client().Disconnect(ctx)
}

// DeviceAuthorizationRepository implementation
func (r *OAuthRepository) SaveDeviceAuth(ctx context.Context, auth *domain.DeviceCode) error {
	collection := r.db.Collection(DeviceAuthCollectionName)
	auth.ID = uuid.NewString()
	auth.CreatedAt = time.Now().UTC()
	_, err := collection.InsertOne(ctx, auth)
	if err != nil {
		return err
	}
	return nil
}

func (r *OAuthRepository) GetDeviceAuthByDeviceCode(ctx context.Context, deviceCode string) (*domain.DeviceCode, error) {
	collection := r.db.Collection(DeviceAuthCollectionName)
	var result domain.DeviceCode
	err := collection.FindOne(ctx, bson.M{"device_code": deviceCode}).Decode(&result)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, serrors.ErrDeviceCodeNotFound
		}
		return nil, err
	}
	return &result, nil
}

func (r *OAuthRepository) GetDeviceAuthByUserCode(ctx context.Context, userCode string) (*domain.DeviceCode, error) {
	collection := r.db.Collection(DeviceAuthCollectionName)
	var result domain.DeviceCode
	filter := bson.M{
		"user_code":  userCode,
		"expires_at": bson.M{"$gt": time.Now().UTC()},
	}
	err := collection.FindOne(ctx, filter).Decode(&result)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, serrors.ErrUserCodeNotFound
		}
		return nil, err
	}
	return &result, nil
}

func (r *OAuthRepository) ApproveDeviceAuth(ctx context.Context, userCode string, userID string) (*domain.DeviceCode, error) {
	collection := r.db.Collection(DeviceAuthCollectionName)
	filter := bson.M{
		"user_code":  userCode,
		"expires_at": bson.M{"$gt": time.Now().UTC()},
		"status":     domain.DeviceCodeStatusPending,
	}
	update := bson.M{
		"$set": bson.M{
			"status":  domain.DeviceCodeStatusAuthorized,
			"user_id": userID,
		},
	}
	opt := options.FindOneAndUpdate().SetReturnDocument(options.After)
	var updatedDoc domain.DeviceCode
	err := collection.FindOneAndUpdate(ctx, filter, update, opt).Decode(&updatedDoc)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, serrors.ErrCannotApproveDeviceAuth
		}
		return nil, err
	}
	return &updatedDoc, nil
}

func (r *OAuthRepository) UpdateDeviceAuthStatus(ctx context.Context, deviceCode string, status domain.DeviceCodeStatus) error {
	collection := r.db.Collection(DeviceAuthCollectionName)
	filter := bson.M{"device_code": deviceCode}
	update := bson.M{"$set": bson.M{"status": status}}
	result, err := collection.UpdateOne(ctx, filter, update)
	if err != nil {
		return err
	}
	if result.MatchedCount == 0 {
		return serrors.ErrDeviceCodeNotFound
	}
	return nil
}

func (r *OAuthRepository) UpdateDeviceAuthLastPolledAt(ctx context.Context, deviceCode string) error {
	collection := r.db.Collection(DeviceAuthCollectionName)
	filter := bson.M{"device_code": deviceCode}
	update := bson.M{"$set": bson.M{"last_polled_at": time.Now().UTC()}}
	result, err := collection.UpdateOne(ctx, filter, update)
	if err != nil {
		return err
	}
	if result.MatchedCount == 0 {
		return serrors.ErrDeviceCodeNotFound
	}
	return nil
}

func (r *OAuthRepository) DeleteExpiredDeviceAuths(ctx context.Context) error {
	collection := r.db.Collection(DeviceAuthCollectionName)
	filter := bson.M{
		"$or": []bson.M{
			{"expires_at": bson.M{"$lte": time.Now().UTC()}},
		},
	}
	_, err := collection.DeleteMany(ctx, filter)
	return err
}
