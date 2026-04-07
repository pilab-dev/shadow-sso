package mongodb

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/pilab-dev/shadow-sso/domain"
	"github.com/rs/zerolog/log"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
)

type TokenRepository struct {
	coll *mongo.Collection
}

func NewTokenRepository(db *mongo.Database) domain.TokenRepository {
	return &TokenRepository{
		coll: db.Collection(TokensCollection),
	}
}

// --- Token Methods (using *domain.Token and *domain.TokenInfo) ---
func (r *TokenRepository) StoreToken(ctx context.Context, token *domain.Token) error {
	_, err := r.coll.InsertOne(ctx, token)
	return err
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
		"token_value": tokenValue, "token_type": "refresh_token",
		"is_revoked": false, "expires_at": bson.M{"$gt": time.Now().UTC()},
	}).Decode(&token)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return nil, errors.New("refresh token not found or invalid")
	}
	return &token, err
}

func (r *TokenRepository) GetRefreshTokenInfo(ctx context.Context, tokenValue string) (*domain.TokenInfo, error) {
	token, err := r.GetRefreshToken(ctx, tokenValue)
	if err != nil {
		return nil, err
	}
	return &domain.TokenInfo{ID: token.ID, TokenType: token.TokenType, ClientID: token.ClientID, UserID: token.UserID, Scope: token.Scope, IssuedAt: token.CreatedAt, ExpiresAt: token.ExpiresAt, IsRevoked: token.IsRevoked, Roles: token.Roles}, nil
}

func (r *TokenRepository) GetAccessTokenInfo(ctx context.Context, tokenValue string) (*domain.TokenInfo, error) {
	token, err := r.GetAccessToken(ctx, tokenValue)
	if err != nil {
		return nil, err
	}
	return &domain.TokenInfo{ID: token.ID, TokenType: token.TokenType, ClientID: token.ClientID, UserID: token.UserID, Scope: token.Scope, IssuedAt: token.CreatedAt, ExpiresAt: token.ExpiresAt, IsRevoked: token.IsRevoked, Roles: token.Roles}, nil
}

func (r *TokenRepository) RevokeRefreshToken(ctx context.Context, tokenValue string) error {
	filter := bson.M{"token_value": tokenValue, "token_type": "refresh_token"}
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
