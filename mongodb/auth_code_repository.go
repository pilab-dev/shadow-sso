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

type AuthCodeRepository struct {
	authCodes  *mongo.Collection
	challenges *mongo.Collection
}

func NewAuthCodeRepository(db *mongo.Database) *AuthCodeRepository {
	return &AuthCodeRepository{
		authCodes:  db.Collection(CodesCollection),
		challenges: db.Collection(ChallengesCollection),
	}
}

// --- Auth Code Methods (using *domain.AuthCode) ---
func (r *AuthCodeRepository) SaveAuthCode(ctx context.Context, authCode *domain.AuthCode) error {
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

func (r *AuthCodeRepository) GetAuthCode(ctx context.Context, codeValue string) (*domain.AuthCode, error) {
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

func (r *AuthCodeRepository) MarkAuthCodeAsUsed(ctx context.Context, codeValue string) error {
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

func (r *AuthCodeRepository) DeleteExpiredAuthCodes(ctx context.Context) error {
	_, err := r.authCodes.DeleteMany(ctx, bson.M{"expires_at": bson.M{"$lte": time.Now().UTC()}})
	return err
}

// --- PKCE Methods ---
func (r *AuthCodeRepository) SaveCodeChallenge(ctx context.Context, code string, challenge string) error {
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

func (r *AuthCodeRepository) GetCodeChallenge(ctx context.Context, code string) (string, error) {
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

func (r *AuthCodeRepository) DeleteCodeChallenge(ctx context.Context, code string) error {
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
