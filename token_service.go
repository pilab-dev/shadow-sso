package ssso

import (
	"context"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/pilab-dev/shadow-sso/api"
	"github.com/pilab-dev/shadow-sso/cache"
	"github.com/rs/zerolog/log"
)

// TokenService handles token generation and validation
type TokenService struct {
	repo   TokenRepository
	cache  cache.TokenStore
	issuer string

	signer *TokenSigner
}

// NewTokenService creates a new TokenService instance
func NewTokenService(
	repo TokenRepository, tokenCache cache.TokenStore, issuer string, signer *TokenSigner,
) *TokenService {
	return &TokenService{
		repo:   repo,
		cache:  tokenCache,
		issuer: issuer,
		signer: signer,
	}
}

type CreateTokenOptions struct {
	// TokenID is the unique ID for the token (UUID)
	TokenID string
	// Scope is the scope for the token (if its an access token)
	Scope string
	// ClientID is the client ID for the token
	ClientID string
	// UserID is the user ID for the token
	UserID string
	// TokenType is either "access_token", "refresh_token", "id_token"
	TokenType string
	// ExpireIn is the expiration time for the token, in duration (e.g. 24h)
	ExpireIn time.Duration
	// SigningKeyID is the ID of the signing key in the TokenSigner. When empty, the default key will be used.
	SigningKeyID string
}

func (s *TokenService) CreateToken(ctx context.Context, opts CreateTokenOptions, claims jwt.Claims) (*Token, error) {
	expiresAt := time.Now().Add(opts.ExpireIn)

	// ? This is a default claim object, it can be used for both access and refresh tokens.
	// ? Later it should be changed to a specific one for access_token, and id_token
	// Access token claims
	tokenClaims := jwt.RegisteredClaims{
		Issuer:    s.issuer,
		Subject:   opts.UserID,
		Audience:  jwt.ClaimStrings{opts.ClientID},
		ExpiresAt: jwt.NewNumericDate(expiresAt),
		IssuedAt:  jwt.NewNumericDate(time.Now()),
		NotBefore: jwt.NewNumericDate(time.Now()),
		ID:        opts.TokenID,
	}

	// Generate access token with the signer
	signedToken, err := s.signer.Sign(tokenClaims, opts.SigningKeyID)
	if err != nil {
		return nil, err
	}

	// Store token in repository
	token := &Token{
		ID:         opts.TokenID,
		TokenType:  opts.TokenType,
		TokenValue: signedToken,
		ClientID:   opts.ClientID,
		UserID:     opts.UserID,
		Scope:      opts.Scope,
		ExpiresAt:  expiresAt,
		CreatedAt:  time.Now(),
		LastUsedAt: time.Now(),
	}
	if err := s.repo.StoreToken(ctx, token); err != nil {
		return nil, err
	}

	if opts.TokenType == api.TokenTypeAccessToken {
		// Store token in cache
		if err := s.cache.Set(ctx, token.ToEntry()); err != nil {
			// return nil, fmt.Errorf("failed to cache token: %w", err)
			log.Warn().Err(err).Msg("failed to cache token")
		}
	}

	return token, nil
}

func (s *TokenService) BuildToken(token *Token) error {
	// ? This is a default claim object, it can be used for both access and refresh tokens.
	// ? Later it should be changed to a specific one for access_token, and id_token
	// Access token claims
	tokenClaims := jwt.RegisteredClaims{
		Issuer:    s.issuer,
		Subject:   token.UserID,
		Audience:  jwt.ClaimStrings{token.ClientID},
		ExpiresAt: jwt.NewNumericDate(token.ExpiresAt),
		IssuedAt:  jwt.NewNumericDate(token.CreatedAt),
		NotBefore: jwt.NewNumericDate(token.CreatedAt),
		ID:        token.ID,
	}

	// Generate access token with the signer
	signedToken, err := s.signer.Sign(tokenClaims, "")
	if err != nil {
		return fmt.Errorf("cannot sign token: %w", err)
	}

	token.TokenValue = signedToken

	return nil
}

// func (s *TokenService) generateUserTokens(ctx context.Context, userID, clientID, scope string) (*TokenResponse, error) {
// 	tokenID := uuid.NewString()

// 	// Generate access token
// 	signedToken, err := s.CreateToken(CreateTokenOptions{
// 		TokenID:      tokenID,
// 		ClientID:     clientID,
// 		UserID:       userID,
// 		Scope:        scope,
// 		ExpireIn:     time.Hour,
// 		TokenType:    "access_token",
// 		SigningKeyID: "", // Use the default
// 	}, nil)
// 	if err != nil {
// 		return nil, err
// 	}

// 	token := &Token{
// 		ID:         tokenID,
// 		TokenType:  "access_token",
// 		TokenValue: signedToken,
// 		ClientID:   clientID,
// 		UserID:     userID,
// 		ExpiresAt:  time.Now().Add(time.Hour),
// 		CreatedAt:  time.Now(),
// 		LastUsedAt: time.Now(),
// 		Scope:      scope,
// 		IsRevoked:  false,
// 	}
// 	if err := s.repo.StoreToken(ctx, token); err != nil {
// 		return nil, err
// 	}

// 	// Generate refresh token
// 	refreshTokenClaims := jwt.RegisteredClaims{
// 		Issuer:  s.issuer,
// 		Subject: userID,
// 		Audience: jwt.ClaimStrings{
// 			clientID,
// 		},
// 		ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour * 24)),
// 		IssuedAt:  jwt.NewNumericDate(time.Now()),
// 		NotBefore: jwt.NewNumericDate(time.Now()),
// 		ID:        refreshTokenID,
// 	}

// 	signedRefreshToken, err := s.signer(refreshTokenClaims)
// 	if err != nil {
// 		return nil, err
// 	}

// 	token = &Token{
// 		ID:         refreshTokenID,
// 		TokenType:  "refresh_token",
// 		TokenValue: signedRefreshToken,
// 		ClientID:   clientID,
// 		UserID:     userID,
// 		ExpiresAt:  refreshTokenClaims.ExpiresAt.Time,
// 		CreatedAt:  time.Now(),
// 		LastUsedAt: time.Now(),
// 	}
// 	if err := s.repo.StoreToken(ctx, token); err != nil {
// 		return nil, err
// 	}

// 	return &TokenResponse{
// 		AccessToken:  signedAccessToken,
// 		TokenType:    "Bearer",
// 		ExpiresIn:    3600,
// 		RefreshToken: signedRefreshToken,
// 		Scope:        scope,
// 	}, nil
// }

// GenerateTokenPair creates a new access and refresh token pair
func (s *TokenService) GenerateTokenPair(ctx context.Context,
	clientID, userID, scope string, tokenTTL time.Duration,
) (*api.TokenResponse, error) {
	// Generate access token
	accessToken := &Token{
		ID:         uuid.NewString(),
		TokenType:  "access_token",
		TokenValue: "",
		ClientID:   clientID,
		UserID:     userID,
		Scope:      scope,
		ExpiresAt:  time.Now().Add(tokenTTL),
		CreatedAt:  time.Now(),
		LastUsedAt: time.Now(),
	}

	if err := s.BuildToken(accessToken); err != nil {
		return nil, fmt.Errorf("failed to build access token: %w", err)
	}

	// Generate refresh token
	refreshToken := &Token{
		ID:         uuid.NewString(),
		TokenType:  "refresh_token",
		TokenValue: uuid.NewString(),
		ClientID:   clientID,
		UserID:     userID,
		Scope:      scope,
		ExpiresAt:  time.Now().Add(tokenTTL * 24), // Refresh tokens live longer
		CreatedAt:  time.Now(),
		LastUsedAt: time.Now(),
	}

	if err := s.BuildToken(refreshToken); err != nil {
		return nil, fmt.Errorf("failed to build refresh token: %w", err)
	}

	// Store tokens
	if err := s.repo.StoreToken(ctx, accessToken); err != nil {
		return nil, fmt.Errorf("failed to store access token: %w", err)
	}

	if err := s.repo.StoreToken(ctx, refreshToken); err != nil {
		return nil, fmt.Errorf("failed to store refresh token: %w", err)
	}

	// Cache access token for faster validation
	if err := s.cache.Set(ctx, accessToken.ToEntry()); err != nil {
		log.Warn().Err(err).Msg("failed to cache access token")
	}

	return &api.TokenResponse{
		IDToken:      "",
		AccessToken:  accessToken.TokenValue,
		TokenType:    "Bearer",
		ExpiresIn:    int(tokenTTL.Seconds()),
		RefreshToken: refreshToken.TokenValue,
	}, nil
}

// ValidateToken validates an access token and returns its information. If the token is revoked or expired,
// it returns ErrTokenExpiredOrRevoked.
func (s *TokenService) ValidateAccessToken(ctx context.Context, tokenValue string) (*Token, error) {
	// Check cache first
	if entry, err := s.cache.Get(ctx, tokenValue); err == nil {
		if !entry.IsRevoked && time.Now().Before(entry.ExpiresAt) {
			var token Token
			token.FromEntry(entry)

			return &token, nil
		}

		_ = s.cache.Delete(ctx, tokenValue)

		return nil, ErrTokenExpiredOrRevoked
	}

	// Check repository
	token, err := s.repo.GetAccessToken(ctx, tokenValue)
	if err != nil {
		return nil, fmt.Errorf("token not found: %w", err)
	}

	if token.IsRevoked || time.Now().After(token.ExpiresAt) {
		return nil, ErrTokenExpiredOrRevoked
	}

	// Cache valid token
	if err := s.cache.Set(ctx, token.ToEntry()); err != nil {
		log.Warn().Err(err).Msg("failed to cache token")
	}

	return token, nil
}

// RevokeToken revokes an access token. This will invalidate the token and remove it from cache
// This is a no-op if the token is already revoked. This is useful for logging out, for example.
func (s *TokenService) RevokeToken(ctx context.Context, token string) error {
	if err := s.cache.Delete(ctx, token); err != nil {
		log.Warn().Err(err).Msg("failed to delete token from cache")
	}

	return s.repo.RevokeToken(ctx, token)
}

// GetRefreshTokenInfo retrieves metadata about a refresh token. Returns the token info if found,
// or an error if not found or database error.
func (s *TokenService) GetRefreshTokenInfo(ctx context.Context, tokenValue string) (*TokenInfo, error) {
	return s.repo.GetRefreshTokenInfo(ctx, tokenValue)
}

// GetAccessTokenInfo retrieves metadata about an access token. Returns the token info if found,
// or an error if not found or database error.
func (s *TokenService) GetAccessTokenInfo(ctx context.Context, tokenValue string) (*TokenInfo, error) {
	return s.repo.GetAccessTokenInfo(ctx, tokenValue)
}
