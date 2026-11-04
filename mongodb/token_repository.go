package mongodb

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/pilab-dev/shadow-sso/domain"
	"github.com/rs/zerolog/log"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

type TokenRepository struct {
	coll *mongo.Collection
}

func NewTokenRepository(ctx context.Context, db *mongo.Database) domain.TokenRepository {
	r := &TokenRepository{
		coll: db.Collection(TokensCollection),
	}
	r.ensureIndexes(ctx)
	return r
}

// ensureIndexes makes token listing and per-session revocation cheap. Failures
// are logged, not fatal: queries still work, just more slowly.
func (r *TokenRepository) ensureIndexes(ctx context.Context) {
	models := []mongo.IndexModel{
		{Keys: bson.D{{Key: "user_id", Value: 1}, {Key: "created_at", Value: -1}}},
		{Keys: bson.D{{Key: "session_id", Value: 1}}},
		{Keys: bson.D{{Key: "family", Value: 1}}},
		{Keys: bson.D{{Key: "expires_at", Value: 1}}},
		// Refresh tokens are looked up by hash; token_value only remains for
		// rows written before hashing was introduced.
		{Keys: bson.D{{Key: "token_hash", Value: 1}}, Options: options.Index().SetUnique(true).SetSparse(true)},
		{Keys: bson.D{{Key: "token_value", Value: 1}}, Options: options.Index().SetSparse(true)},
	}
	if _, err := r.coll.Indexes().CreateMany(ctx, models); err != nil {
		log.Warn().Err(err).Msg("Failed to create token indexes")
	}
}

// --- Token Methods (using *domain.Token and *domain.TokenInfo) ---
func (r *TokenRepository) StoreToken(ctx context.Context, token *domain.Token) error {
	stored := prepareTokenForStorage(token)
	_, err := r.coll.InsertOne(ctx, stored)
	return err
}

// prepareTokenForStorage returns a copy of token that is safe to persist:
// refresh tokens are stored only as a SHA-256 hash. The caller's token is left
// untouched so callers that still need the raw value (e.g. to return it in a
// token response) keep it.
func prepareTokenForStorage(token *domain.Token) *domain.Token {
	if token == nil {
		return nil
	}
	stored := *token
	if stored.TokenType != "refresh_token" {
		return &stored
	}
	if stored.TokenHash == "" && stored.TokenValue != "" {
		stored.TokenHash = hashTokenValue(stored.TokenValue)
	}
	// Hashed refresh tokens at rest: never persist the raw JWT.
	stored.TokenValue = ""
	return &stored
}

func (r *TokenRepository) GetAccessToken(ctx context.Context, tokenValue string) (*domain.Token, error) {
	var token domain.Token
	err := r.coll.FindOne(ctx, bson.M{
		"token_value": tokenValue, "token_type": "access_token",
		"is_revoked": false, "expires_at": bson.M{"$gt": time.Now().UTC()},
	}).Decode(&token)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return nil, errors.New("token not found or invalid")
	}
	return &token, err
}

func (r *TokenRepository) RevokeToken(ctx context.Context, tokenValue string) error {
	_, err := r.coll.UpdateOne(ctx, bson.M{"token_value": tokenValue, "token_type": "access_token"}, bson.M{"$set": bson.M{"is_revoked": true}})
	return err
}

func (r *TokenRepository) GetRefreshToken(ctx context.Context, tokenValue string) (*domain.Token, error) {
	var token domain.Token
	err := r.coll.FindOne(ctx, bson.M{
		"$or": []bson.M{
			{"token_value": tokenValue},
			{"token_hash": hashTokenValue(tokenValue)},
		},
		"token_type": "refresh_token",
		"is_revoked": false, "expires_at": bson.M{"$gt": time.Now().UTC()},
	}).Decode(&token)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return nil, errors.New("refresh token not found or invalid")
	}
	// Dual-read: backfill the hash for legacy rows and drop the raw value so it
	// is never stored in replayable form again.
	if token.TokenHash == "" && token.TokenValue != "" {
		token.TokenHash = hashTokenValue(token.TokenValue)
		_, _ = r.coll.UpdateOne(ctx, bson.M{"_id": token.ID}, bson.M{
			"$set":   bson.M{"token_hash": token.TokenHash},
			"$unset": bson.M{"token_value": ""},
		})
	}
	return &token, err
}

// GetRefreshTokenInfo returns token metadata for the refresh grant. Unlike
// GetRefreshToken it does not filter on revocation, because the refresh flow
// must be able to tell "revoked because rotated" (replay) from "unknown token".
func (r *TokenRepository) GetRefreshTokenInfo(ctx context.Context, tokenValue string) (*domain.TokenInfo, error) {
	var token domain.Token
	err := r.coll.FindOne(ctx, bson.M{
		"$or": []bson.M{
			{"token_value": tokenValue},
			{"token_hash": hashTokenValue(tokenValue)},
		},
		"token_type": "refresh_token",
	}).Decode(&token)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, errors.New("refresh token not found or invalid")
		}
		return nil, err
	}
	return &domain.TokenInfo{
		ID:                 token.ID,
		TokenType:          token.TokenType,
		ClientID:           token.ClientID,
		UserID:             token.UserID,
		Scope:              token.Scope,
		IssuedAt:           token.CreatedAt,
		ExpiresAt:          token.ExpiresAt,
		IsRevoked:          token.IsRevoked,
		Roles:              token.Roles,
		RefreshTokenFamily: token.Family,
		SessionID:          token.SessionID,
		UsedAt:             token.UsedAt,
		CnfJKT:             token.CnfJKT,
	}, nil
}

func (r *TokenRepository) GetAccessTokenInfo(ctx context.Context, tokenValue string) (*domain.TokenInfo, error) {
	token, err := r.GetAccessToken(ctx, tokenValue)
	if err != nil {
		return nil, err
	}
	return &domain.TokenInfo{ID: token.ID, TokenType: token.TokenType, ClientID: token.ClientID, UserID: token.UserID, Scope: token.Scope, IssuedAt: token.CreatedAt, ExpiresAt: token.ExpiresAt, IsRevoked: token.IsRevoked, Roles: token.Roles}, nil
}

func (r *TokenRepository) RevokeRefreshToken(ctx context.Context, tokenValue string) error {
	filter := bson.M{"$or": []bson.M{
		{"token_value": tokenValue},
		{"token_hash": hashTokenValue(tokenValue)},
	}, "token_type": "refresh_token"}
	update := bson.M{"$set": bson.M{"is_revoked": true}}
	result, err := r.coll.UpdateOne(ctx, filter, update)
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

// MarkRefreshTokenUsed records a successful rotation. Presenting the same token
// again is treated as replay by the refresh grant.
func (r *TokenRepository) MarkRefreshTokenUsed(ctx context.Context, tokenValue, rotatedTo string) error {
	set := bson.M{"used_at": time.Now().UTC()}
	if rotatedTo != "" {
		set["rotated_to"] = rotatedTo
	}
	_, err := r.coll.UpdateOne(ctx,
		bson.M{"$or": []bson.M{
			{"token_value": tokenValue},
			{"token_hash": hashTokenValue(tokenValue)},
		}, "token_type": "refresh_token"},
		bson.M{"$set": set},
	)
	return err
}

// RevokeTokenFamily revokes every token in a rotation family. Called when a
// refresh token is replayed, which indicates theft.
func (r *TokenRepository) RevokeTokenFamily(ctx context.Context, family string) error {
	if family == "" {
		return nil
	}
	_, err := r.coll.UpdateMany(ctx, bson.M{"family": family}, bson.M{"$set": bson.M{"is_revoked": true}})
	return err
}

// RevokeTokensBySessionID revokes every token issued for a session, so kicking a
// device also kills its access and refresh tokens.
func (r *TokenRepository) RevokeTokensBySessionID(ctx context.Context, sessionID string) error {
	if sessionID == "" {
		return nil
	}
	_, err := r.coll.UpdateMany(ctx, bson.M{"session_id": sessionID}, bson.M{"$set": bson.M{"is_revoked": true}})
	return err
}

func (r *TokenRepository) RevokeAllUserTokens(ctx context.Context, userID string) error {
	_, err := r.coll.UpdateMany(ctx, bson.M{"user_id": userID}, bson.M{"$set": bson.M{"is_revoked": true}})
	return err
}

func (r *TokenRepository) RevokeAllClientTokens(ctx context.Context, clientID string) error {
	_, err := r.coll.UpdateMany(ctx, bson.M{"client_id": clientID}, bson.M{"$set": bson.M{"is_revoked": true}})
	return err
}

func (r *TokenRepository) DeleteExpiredTokens(ctx context.Context) error {
	_, err := r.coll.DeleteMany(ctx, bson.M{"expires_at": bson.M{"$lte": time.Now().UTC()}})
	return err
}

func (r *TokenRepository) ValidateAccessToken(ctx context.Context, tokenValue string) (string, error) {
	token, err := r.GetAccessToken(ctx, tokenValue)
	if err != nil {
		return "", err
	}
	return token.UserID, nil
}

func (r *TokenRepository) GetTokenInfo(ctx context.Context, tokenValue string) (*domain.Token, error) {
	var token domain.Token
	err := r.coll.FindOne(ctx, bson.M{"token_value": tokenValue, "is_revoked": false, "expires_at": bson.M{"$gt": time.Now().UTC()}}).Decode(&token)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return nil, errors.New("token not found or invalid")
	}
	return &token, err
}

// ListByUserID returns token metadata for a user, newest first. Token values
// are intentionally not selectable here: the admin and traceability surfaces
// must never expose bearer credentials.
func (r *TokenRepository) ListByUserID(ctx context.Context, filter domain.TokenFilter, limit, offset int) ([]*domain.Token, error) {
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	if offset < 0 {
		offset = 0
	}
	opts := options.Find().
		SetSort(bson.D{{Key: "created_at", Value: -1}}).
		SetSkip(int64(offset)).
		SetLimit(int64(limit)).
		SetProjection(bson.M{"token_value": 0})

	cursor, err := r.coll.Find(ctx, buildTokenFilter(filter), opts)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var tokens []*domain.Token
	if err := cursor.All(ctx, &tokens); err != nil {
		return nil, err
	}
	return tokens, nil
}

// CountByUserID returns the number of tokens matching the filter.
func (r *TokenRepository) CountByUserID(ctx context.Context, filter domain.TokenFilter) (int64, error) {
	return r.coll.CountDocuments(ctx, buildTokenFilter(filter))
}

// GetTokenByID looks up a token by JTI regardless of revocation or expiry.
// The token value is loaded for internal revocation but never leaves the
// server.
func (r *TokenRepository) GetTokenByID(ctx context.Context, id string) (*domain.Token, error) {
	var token domain.Token
	err := r.coll.FindOne(ctx, bson.M{"_id": id}).Decode(&token)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return nil, errors.New("token not found")
	}
	return &token, err
}

func buildTokenFilter(filter domain.TokenFilter) bson.M {
	query := bson.M{}
	if filter.UserID != "" {
		query["user_id"] = filter.UserID
	}
	if filter.ClientID != "" {
		query["client_id"] = filter.ClientID
	}
	if filter.SessionID != "" {
		query["session_id"] = filter.SessionID
	}
	if filter.TokenType != "" {
		query["token_type"] = filter.TokenType
	}
	if !filter.IncludeRevoked {
		query["is_revoked"] = bson.M{"$ne": true}
	}
	if !filter.IncludeExpired {
		now := filter.Now
		if now.IsZero() {
			now = time.Now().UTC()
		}
		query["expires_at"] = bson.M{"$gt": now}
	}
	return query
}

// ListUnauditedExpired returns tokens that have expired but have not yet
// produced a TokenExpired audit event.
func (r *TokenRepository) ListUnauditedExpired(ctx context.Context, before time.Time, limit int) ([]*domain.Token, error) {
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	opts := options.Find().
		SetSort(bson.D{{Key: "expires_at", Value: 1}}).
		SetLimit(int64(limit)).
		SetProjection(bson.M{"token_value": 0})
	cursor, err := r.coll.Find(ctx, bson.M{
		"expires_at":        bson.M{"$lte": before},
		"expiry_audited_at": bson.M{"$exists": false},
	}, opts)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var tokens []*domain.Token
	if err := cursor.All(ctx, &tokens); err != nil {
		return nil, err
	}
	return tokens, nil
}

// MarkExpiryAudited records that a TokenExpired event was emitted.
func (r *TokenRepository) MarkExpiryAudited(ctx context.Context, ids []string) error {
	if len(ids) == 0 {
		return nil
	}
	now := time.Now().UTC()
	_, err := r.coll.UpdateMany(ctx,
		bson.M{"_id": bson.M{"$in": ids}},
		bson.M{"$set": bson.M{"expiry_audited_at": now}})
	return err
}

// hashTokenValue returns the SHA-256 hex digest of a raw token value.
func hashTokenValue(v string) string {
	sum := sha256.Sum256([]byte(v))
	return hex.EncodeToString(sum[:])
}
