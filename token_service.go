package ssso

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
)

// TokenService handles token generation and validation
type TokenService struct {
	repo     OAuthRepository
	cache    TokenStore
	issuer   string
	tokenTTL time.Duration
}

// NewTokenService creates a new TokenService instance
func NewTokenService(repo OAuthRepository, cache TokenStore, issuer string, tokenTTL time.Duration) *TokenService {
	return &TokenService{
		repo:     repo,
		cache:    cache,
		issuer:   issuer,
		tokenTTL: tokenTTL,
	}
}

// GenerateTokenPair creates a new access and refresh token pair
func (s *TokenService) GenerateTokenPair(ctx context.Context, clientID, userID, scope string) (*TokenResponse, error) {
	// Generate access token
	accessToken := &Token{
		ID:         uuid.NewString(),
		TokenType:  "access_token",
		TokenValue: uuid.NewString(),
		ClientID:   clientID,
		UserID:     userID,
		Scope:      scope,
		ExpiresAt:  time.Now().Add(s.tokenTTL),
		CreatedAt:  time.Now(),
		LastUsedAt: time.Now(),
	}

	// Generate refresh token
	refreshToken := &Token{
		ID:         uuid.NewString(),
		TokenType:  "refresh_token",
		TokenValue: uuid.NewString(),
		ClientID:   clientID,
		UserID:     userID,
		Scope:      scope,
		ExpiresAt:  time.Now().Add(s.tokenTTL * 24), // Refresh tokens live longer
		CreatedAt:  time.Now(),
		LastUsedAt: time.Now(),
	}

	// Store tokens
	if err := s.repo.StoreToken(ctx, accessToken); err != nil {
		return nil, fmt.Errorf("failed to store access token: %w", err)
	}

	if err := s.repo.StoreToken(ctx, refreshToken); err != nil {
		return nil, fmt.Errorf("failed to store refresh token: %w", err)
	}

	// Cache access token for faster validation
	if err := s.cache.Set(ctx, accessToken); err != nil {
		log.Warn().Err(err).Msg("failed to cache access token")
	}

	return &TokenResponse{
		AccessToken:  accessToken.TokenValue,
		TokenType:    "Bearer",
		ExpiresIn:    int(s.tokenTTL.Seconds()),
		RefreshToken: refreshToken.TokenValue,
		Scope:        scope,
	}, nil
}

// ValidateToken validates an access token and returns its information
func (s *TokenService) ValidateToken(ctx context.Context, tokenValue string) (*Token, error) {
	// Check cache first
	if token, found := s.cache.Get(ctx, tokenValue); found {
		if !token.IsRevoked && time.Now().Before(token.ExpiresAt) {
			return token, nil
		}
		s.cache.Delete(ctx, tokenValue)
		return nil, fmt.Errorf("token is invalid or expired")
	}

	// Check repository
	token, err := s.repo.GetAccessToken(ctx, tokenValue)
	if err != nil {
		return nil, fmt.Errorf("token not found: %w", err)
	}

	if token.IsRevoked || time.Now().After(token.ExpiresAt) {
		return nil, fmt.Errorf("token is invalid or expired")
	}

	// Cache valid token
	if err := s.cache.Set(ctx, token); err != nil {
		log.Warn().Err(err).Msg("failed to cache token")
	}

	return token, nil
}
