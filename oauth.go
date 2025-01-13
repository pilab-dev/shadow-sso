package ssso

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// GenerateAuthCode generates a new authorization code for OAuth2 authorization code flow.
// It creates a secure random code and stores it with the provided client details.
func (s *OAuthService) GenerateAuthCode(clientID, redirectURI, scope string) (string, error) {
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

	if err := s.oauthRepo.SaveAuthCode(authCode); err != nil {
		return "", fmt.Errorf("failed to save auth code: %w", err)
	}

	return code, nil
}

// GenerateTokens exchanges an authorization code for access and refresh tokens.
// It validates the code and client ID before generating new tokens.
func (s *OAuthService) GenerateTokens(code, clientID string) (*TokenResponse, error) {
	// Get and validate the stored auth code
	authCode, err := s.oauthRepo.GetAuthCode(code)
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
	accessToken := uuid.New().String()
	refreshToken := uuid.New().String()
	expiresAt := time.Now().Add(time.Hour)

	// Create token record
	token := &Token{
		ID:         uuid.New().String(),
		TokenType:  "access_token",
		TokenValue: accessToken,
		ClientID:   clientID,
		Scope:      authCode.Scope,
		ExpiresAt:  expiresAt,
		CreatedAt:  time.Now(),
		LastUsedAt: time.Now(),
	}

	if err := s.oauthRepo.StoreToken(token); err != nil {
		return nil, fmt.Errorf("failed to store token: %w", err)
	}

	// Mark auth code as used
	if err := s.oauthRepo.MarkAuthCodeAsUsed(code); err != nil {
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
func (s *OAuthService) ValidateToken(token string) (string, error) {
	return s.oauthRepo.ValidateAccessToken(token)
}

// GetUserInfo retrieves user information for a valid access token.
func (s *OAuthService) GetUserInfo(token string) (map[string]interface{}, error) {
	userID, err := s.oauthRepo.ValidateAccessToken(token)
	if err != nil {
		return nil, fmt.Errorf("invalid access token: %w", err)
	}

	return s.oauthRepo.GetUserInfo(userID)
}

// RevokeToken revokes an access token.
func (s *OAuthService) RevokeToken(token string) error {
	return s.oauthRepo.RevokeToken(token)
}
