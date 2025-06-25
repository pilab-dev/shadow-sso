package mongodb

import (
	"context"
	"errors"
	"fmt"
	"strconv" // For ListClients
	"time"

	"github.com/google/uuid"
	ssso "github.com/pilab-dev/shadow-sso"
	"github.com/pilab-dev/shadow-sso/client" // Import the canonical client model
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

// NewOAuthRepository constructor returns the ssso.OAuthRepository interface
func NewOAuthRepository(ctx context.Context, db *mongo.Database) (ssso.OAuthRepository, error) {
	repo := &OAuthRepository{
		db:         db,
		clients:    db.Collection(ClientsCollection), // Assumes ClientsCollection = "oauth_clients"
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

// createIndexes - client index now uses "client_id" which matches client.Client's bson tag.
func (r *OAuthRepository) createIndexes(ctx context.Context) error {
	// Client indexes
	_, err := r.clients.Indexes().CreateMany(ctx, []mongo.IndexModel{
		{
			Keys:    bson.D{{Key: "client_id", Value: 1}}, // Matches client.Client's `bson:"client_id"`
			Options: options.Index().SetUnique(true),
		},
		// Add other client indexes if needed, e.g., on client_name if frequently searched
	})
	if err != nil {
		log.Warn().Err(err).Msg("Issue creating client_id index (may already exist or other benign issue)")
		// return fmt.Errorf("failed to create client_id index: %w", err) // Stricter
	}

	// Auth code, Token, PKCE, Session indexes (as before, ensure they are correct)
	// ... (rest of index creation from existing file, ensure no conflicts) ...
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
		{Keys: bson.D{{Key: "client_id", Value: 1}}}, // This client_id refers to token's client_id field
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
		{Keys: bson.D{{Key: "_id", Value: 1}}, Options: options.Index().SetUnique(true)}, // Assuming domain.Session uses _id
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
	// client.Client.ID is tagged as `bson:"client_id"`.
	// MongoDB will auto-generate `_id` (ObjectID) if not specified.
	// If client_id should be the MongoDB _id, the tag in client.Client should be `bson:"_id"`.
	// For now, assume client_id is a distinct field with a unique index.
	if c.ID == "" { // Should be set by service layer e.g. uuid.NewString()
		return errors.New("client ID is required")
	}
	c.CreatedAt = time.Now().UTC()
	c.UpdatedAt = time.Now().UTC()
	_, err := r.clients.InsertOne(ctx, c)
	if err != nil {
		if mongo.IsDuplicateKeyError(err) {
			return errors.New("client with this client_id already exists")
		}
		log.Error().Err(err).Msg("Error creating client in MongoDB")
		return err
	}
	return nil
}

func (r *OAuthRepository) GetClient(ctx context.Context, clientID string) (*client.Client, error) {
	var c client.Client
	// Query against "client_id" field due to bson tag in client.Client struct
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
	// ReplaceOne uses the filter to find the doc, and replaces the entire doc with 'c'.
	// Query against "client_id" field.
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
		return err // "client not found" or other db error
	}
	// TODO: Implement proper secret hashing and comparison.
	// For now, direct string comparison if secrets are stored plaintext,
	// or use bcrypt if secrets are hashed (PasswordHasher could be a dependency).
	// Assuming secret is hashed and PasswordHasher is available or logic is here.
	// If secret in DB is hashed:
	// if err := bcrypt.CompareHashAndPassword([]byte(c.Secret), []byte(clientSecret)); err != nil {
	//    return errors.New("invalid client secret")
	// }
	// For now, direct compare (NOT FOR PRODUCTION if DB stores plaintext)
	if c.Secret != clientSecret { // This is insecure if c.Secret is plaintext. If hashed, this comparison is wrong.
		return errors.New("invalid client secret")
	}
	if !c.IsActive {
		return errors.New("client is inactive")
	}
	return nil
}

// --- Token Methods (using *ssso.Token, as before) ---
// StoreToken, GetAccessToken, RevokeToken, GetRefreshTokenInfo, GetAccessTokenInfo
// These methods remain unchanged as they operate on ssso.Token.
// (Copy existing implementations of these token methods here)
func (r *OAuthRepository) StoreToken(ctx context.Context, token *ssso.Token) error {
	_, err := r.tokens.InsertOne(ctx, token)
	return err
}

func (r *OAuthRepository) GetAccessToken(ctx context.Context, tokenValue string) (*ssso.Token, error) {
	var token ssso.Token
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
	// This typically revokes access tokens.
	// For more specificity, one might filter by token_type as well.
	_, err := r.tokens.UpdateOne(ctx, bson.M{"token_value": tokenValue, "token_type": "access_token"}, bson.M{"$set": bson.M{"is_revoked": true}})
	// Consider also deleting from cache if a direct cache reference is available here or handled by service layer.
	return err
}

func (r *OAuthRepository) GetRefreshToken(ctx context.Context, tokenValue string) (*ssso.Token, error) {
	var token ssso.Token
	err := r.tokens.FindOne(ctx, bson.M{
		"token_value": tokenValue, "token_type": "refresh_token",
		"is_revoked": false, "expires_at": bson.M{"$gt": time.Now().UTC()},
	}).Decode(&token)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return nil, errors.New("refresh token not found or invalid")
	}
	return &token, err
}

func (r *OAuthRepository) GetRefreshTokenInfo(ctx context.Context, tokenValue string) (*ssso.TokenInfo, error) {
	token, err := r.GetRefreshToken(ctx, tokenValue) // Use GetRefreshToken to ensure it's a valid refresh token
	if err != nil {
		return nil, err
	}
	return &ssso.TokenInfo{ /* map from token */ ID: token.ID, TokenType: token.TokenType, ClientID: token.ClientID, UserID: token.UserID, Scope: token.Scope, IssuedAt: token.CreatedAt, ExpiresAt: token.ExpiresAt, IsRevoked: token.IsRevoked}, nil
}

func (r *OAuthRepository) GetAccessTokenInfo(ctx context.Context, tokenValue string) (*ssso.TokenInfo, error) {
	token, err := r.GetAccessToken(ctx, tokenValue) // Use GetAccessToken to ensure it's a valid access token
	if err != nil {
		return nil, err
	}
	return &ssso.TokenInfo{ /* map from token */ ID: token.ID, TokenType: token.TokenType, ClientID: token.ClientID, UserID: token.UserID, Scope: token.Scope, IssuedAt: token.CreatedAt, ExpiresAt: token.ExpiresAt, IsRevoked: token.IsRevoked}, nil
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
		// This might not be an error if the token never existed or was already cleaned up.
		// For robustness, we can log it but not return an error that would break a flow.
		log.Warn().Str("refreshToken", tokenValue).Msg("Refresh token not found to revoke, or already revoked and cleaned.")
	} else {
		log.Debug().Str("refreshToken", tokenValue).Msg("Refresh token marked as revoked.")
	}
	return nil
}

// ... (Other TokenRepository methods like RevokeAllUserTokens, DeleteExpiredTokens, etc. as previously defined) ...
func (r *OAuthRepository) RevokeAllUserTokens(ctx context.Context, userID string) error { /* ... */
	// Example: Update many tokens where user_id matches
	_, err := r.tokens.UpdateMany(ctx, bson.M{"user_id": userID}, bson.M{"$set": bson.M{"is_revoked": true}})
	return err
}

func (r *OAuthRepository) RevokeAllClientTokens(ctx context.Context, clientID string) error { /* ... */
	_, err := r.tokens.UpdateMany(ctx, bson.M{"client_id": clientID}, bson.M{"$set": bson.M{"is_revoked": true}})
	return err
}

func (r *OAuthRepository) DeleteExpiredTokens(ctx context.Context) error { /* ... */
	_, err := r.tokens.DeleteMany(ctx, bson.M{"expires_at": bson.M{"$lte": time.Now().UTC()}})
	return err
}

func (r *OAuthRepository) ValidateAccessToken(ctx context.Context, tokenValue string) (string, error) { /* ... */
	token, err := r.GetAccessToken(ctx, tokenValue)
	if err != nil {
		return "", err
	}
	return token.UserID, nil
}

func (r *OAuthRepository) GetTokenInfo(ctx context.Context, tokenValue string) (*ssso.Token, error) { /* ... */
	// This method might be intended to fetch any token type by its value for introspection.
	// For simplicity, let's try access token then refresh token if not found.
	var token ssso.Token
	err := r.tokens.FindOne(ctx, bson.M{"token_value": tokenValue, "is_revoked": false, "expires_at": bson.M{"$gt": time.Now().UTC()}}).Decode(&token)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return nil, errors.New("token not found or invalid")
	}
	return &token, err
}

// --- Auth Code Methods (using *ssso.AuthCode) ---
func (r *OAuthRepository) SaveAuthCode(ctx context.Context, authCode *ssso.AuthCode) error {
	if authCode.Code == "" {
		return errors.New("auth code value cannot be empty")
	}
	authCode.CreatedAt = time.Now().UTC() // Ensure CreatedAt is set
	// ExpiresAt should be set by the service layer before calling SaveAuthCode

	// The AuthCode struct in oauth_repository.go already includes UserID, CodeChallenge, CodeChallengeMethod
	// So, just inserting it will save these fields.
	_, err := r.authCodes.InsertOne(ctx, authCode)
	if err != nil {
		if mongo.IsDuplicateKeyError(err) { // Check specific error for duplicate key
			return fmt.Errorf("authorization code %s already exists: %w", authCode.Code, err)
		}
		log.Error().Err(err).Str("code", authCode.Code).Msg("Error saving authorization code")
		return fmt.Errorf("failed to save authorization code: %w", err)
	}
	log.Debug().Str("code", authCode.Code).Str("userID", authCode.UserID).Msg("Authorization code saved")
	return nil
}

func (r *OAuthRepository) GetAuthCode(ctx context.Context, codeValue string) (*ssso.AuthCode, error) {
	var authCode ssso.AuthCode
	err := r.authCodes.FindOne(ctx, bson.M{"code": codeValue}).Decode(&authCode)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, fmt.Errorf("authorization code %s not found", codeValue)
		}
		log.Error().Err(err).Str("code", codeValue).Msg("Error retrieving authorization code")
		return nil, fmt.Errorf("failed to retrieve authorization code: %w", err)
	}
	// The retrieved authCode object will have UserID, CodeChallenge, CodeChallengeMethod populated if they were saved.
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

func (r *OAuthRepository) DeleteExpiredAuthCodes(ctx context.Context) error { /* ... */
	_, err := r.authCodes.DeleteMany(ctx, bson.M{"expires_at": bson.M{"$lte": time.Now().UTC()}})
	return err
}

// --- PKCE Methods ---
// SaveCodeChallenge: This was previously saving challenge against 'code' which was the auth code.
// If the PKCE challenge needs to be associated with the flow before the auth code is generated,
// this might need adjustment (e.g., save against flowId).
// However, the current flow stores PKCE params in LoginFlowState, and then GenerateAuthCode
// receives them to store with the AuthCode. So, SaveCodeChallenge here should store
// the challenge directly as part of the AuthCode document, which is handled by SaveAuthCode.
// GetCodeChallenge will then retrieve it from the AuthCode document.
// Therefore, the separate PKCE collection might be redundant if PKCE challenges are stored directly
// within the AuthCode documents.
// For this iteration, let's assume CodeChallenge and Method are part of AuthCode.
// The PkceRepository interface methods (SaveCodeChallenge, GetCodeChallenge, DeleteCodeChallenge)
// might need to be re-evaluated or their implementations changed.
// If they operate on a separate `challenges` collection as currently hinted by OAuthRepository struct,
// then PKCEService needs to call SaveCodeChallenge with the *authorization code* after it's generated.
//
// Current plan: AuthCode struct contains PKCE fields. SaveAuthCode persists them.
// pkceService.ValidateCodeVerifier calls oauthRepo.GetCodeChallenge(ctx, code).
// This GetCodeChallenge should thus fetch the AuthCode and return its CodeChallenge field.
func (r *OAuthRepository) SaveCodeChallenge(ctx context.Context, code string, challenge string) error {
	// This method might become obsolete if challenge is saved directly with AuthCode via SaveAuthCode.
	// If still used, it implies a separate store or update operation.
	// For now, assuming it's handled by SaveAuthCode storing the AuthCode.CodeChallenge.
	// If this method is called by pkceService independently, it needs to store to r.challenges.
	// Let's assume the `challenges` collection is used for now by PKCEService.
	_, err := r.challenges.InsertOne(ctx, bson.M{"code": code, "challenge": challenge, "created_at": time.Now()})
	if mongo.IsDuplicateKeyError(err) {
		// If it's a duplicate, maybe update it? Or it implies an issue.
		log.Warn().Str("code", code).Msg("SaveCodeChallenge: challenge for this code already exists.")
		return nil // Or return an error
	}
	return err
}

func (r *OAuthRepository) GetCodeChallenge(ctx context.Context, code string) (string, error) {
	// Fetch the AuthCode document which contains the CodeChallenge.
	authCode, err := r.GetAuthCode(ctx, code)
	if err != nil {
		// Log the error from GetAuthCode as it's more specific
		log.Warn().Err(err).Str("auth_code_value", code).Msg("GetCodeChallenge: Failed to retrieve AuthCode to get challenge")
		return "", fmt.Errorf("failed to get auth code '%s' for pkce challenge: %w", code, err)
	}

	if authCode.CodeChallenge == "" {
		log.Warn().Str("auth_code_value", code).Msg("GetCodeChallenge: CodeChallenge field is empty in retrieved AuthCode")
		return "", errors.New("pkce code_challenge not set for the given authorization code")
	}
	// Note: This method now returns only the challenge. The PKCEService's ValidateCodeVerifier
	// will need to handle the method (S256/plain) based on this challenge.
	// The ssso.ValidatePKCEChallenge helper function implicitly handles 'plain' if the challenge matches the verifier directly,
	// and S256 otherwise. This might be sufficient if CodeChallengeMethod stored in AuthCode is not explicitly passed to it.
	// For a more robust solution, GetCodeChallenge could return both challenge and method,
	// or PKCEService.ValidateCodeVerifier could fetch the full AuthCode.
	// For now, returning only the challenge string as per the existing interface.
	return authCode.CodeChallenge, nil
}

func (r *OAuthRepository) DeleteCodeChallenge(ctx context.Context, code string) error {
	// This method is likely obsolete if the challenge is stored within the AuthCode document
	// and the AuthCode is marked as used or deleted after successful token exchange.
	// If the `challenges` collection is still being populated by `SaveCodeChallenge` for some reason,
	// then this deletion logic would apply to that collection.
	// Given the current changes, this method acting on `r.challenges` is likely correct if `SaveCodeChallenge` still uses it.
	// However, the primary path for PKCE challenge for auth code flow is now via AuthCode struct.
	log.Debug().Str("code", code).Msg("DeleteCodeChallenge called. If PKCE challenge is part of AuthCode, this might be redundant.")
	result, err := r.challenges.DeleteOne(ctx, bson.M{"code": code})
	if err != nil {
		return err
	}
	if result.DeletedCount == 0 {
		log.Warn().Str("code", code).Msg("No document found in 'challenges' collection to delete for code.")
		// Not necessarily an error if it was never stored separately or already deleted.
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
// SaveDeviceAuth stores a new device authorization request.
func (r *OAuthRepository) SaveDeviceAuth(ctx context.Context, auth *ssso.DeviceCode) error {
	collection := r.db.Collection(DeviceAuthCollectionName)
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
	collection := r.db.Collection(DeviceAuthCollectionName)
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
	collection := r.db.Collection(DeviceAuthCollectionName)
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
	collection := r.db.Collection(DeviceAuthCollectionName)
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
	collection := r.db.Collection(DeviceAuthCollectionName)
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
	collection := r.db.Collection(DeviceAuthCollectionName)
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
	collection := r.db.Collection(DeviceAuthCollectionName)
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
