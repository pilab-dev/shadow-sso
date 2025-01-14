package ssso

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
)

// GenerateAuthCode generates a new authorization code for OAuth2 authorization code flow.
// It creates a secure random code and stores it with the provided client details.
func (s *OAuthService) GenerateAuthCode(ctx context.Context, clientID, redirectURI, scope string) (string, error) {
	// Generate secure random bytes for auth code
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %w", err)
	}
	code := base64.StdEncoding.EncodeToString(b)

	// Create auth code record
	authCode := &AuthCode{
		Code:        code,
		ClientID:    clientID,
		RedirectURI: redirectURI,
		Scope:       scope,
		ExpiresAt:   time.Now().Add(10 * time.Minute),
		CreatedAt:   time.Now(),
	}

	if err := s.oauthRepo.SaveAuthCode(ctx, authCode); err != nil {
		return "", fmt.Errorf("failed to save auth code: %w", err)
	}

	return code, nil
}

// GenerateTokens exchanges an authorization code for access and refresh tokens.
// It validates the code and client ID before generating new tokens.
func (s *OAuthService) GenerateTokens(ctx context.Context, code, clientID string) (*TokenResponse, error) {
	// Get and validate the stored auth code
	authCode, err := s.oauthRepo.GetAuthCode(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("invalid auth code: %w", err)
	}

	if authCode.ClientID != clientID {
		return nil, fmt.Errorf("client ID mismatch")
	}

	if authCode.Used {
		return nil, fmt.Errorf("auth code already used")
	}

	if time.Now().After(authCode.ExpiresAt) {
		return nil, fmt.Errorf("auth code expired")
	}

	// Generate new tokens
	accessToken := uuid.NewString()
	refreshToken := uuid.NewString()
	expiresAt := time.Now().Add(time.Hour)

	// Create token record
	token := &Token{
		ID:         uuid.NewString(),
		TokenType:  "access_token",
		TokenValue: accessToken,
		ClientID:   clientID,
		Scope:      authCode.Scope,
		ExpiresAt:  expiresAt,
		CreatedAt:  time.Now(),
		LastUsedAt: time.Now(),
	}

	if err := s.oauthRepo.StoreToken(ctx, token); err != nil {
		return nil, fmt.Errorf("failed to store token: %w", err)
	}

	// Mark auth code as used
	if err := s.oauthRepo.MarkAuthCodeAsUsed(ctx, code); err != nil {
		return nil, fmt.Errorf("failed to mark auth code as used: %w", err)
	}

	return &TokenResponse{
		AccessToken:  accessToken,
		TokenType:    "Bearer",
		ExpiresIn:    3600,
		RefreshToken: refreshToken,
	}, nil
}

// ValidateToken validates an access token and returns the associated user ID.
func (s *OAuthService) ValidateToken(ctx context.Context, token string) (string, error) {
	return s.oauthRepo.ValidateAccessToken(ctx, token)
}

// GetUserInfo retrieves user information for a valid access token.
func (s *OAuthService) GetUserInfo(ctx context.Context, token string) (map[string]interface{}, error) {
	userID, err := s.oauthRepo.ValidateAccessToken(ctx, token)
	if err != nil {
		return nil, fmt.Errorf("invalid access token: %w", err)
	}

	_ = userID

	log.Error().Msg("GetUserInfo not implemented")

	// return s.userRepo.GetUserInfo(ctx, userID)
	return nil, nil
}

// RevokeToken revokes an access token.
func (s *OAuthService) RevokeToken(ctx context.Context, token string) error {
	return s.oauthRepo.RevokeToken(ctx, token)
}
