package domain

import (
	"context"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/pilab-dev/shadow-sso/api"
)

type CreateTokenOptions struct {
	TokenID            string
	Scope              string
	ClientID           string
	UserID             string
	TokenType          string
	ExpireIn           time.Duration
	SigningKeyID       string
	RefreshTokenFamily string
	// SessionID is the ID of the session that issued the token. When set, it is
	// emitted as the `sid` claim for logout correlation.
	SessionID string
	// Roles to include in the token. When set, these are used directly
	// instead of looking up roles from the user repository.
	// This is useful for client_credentials tokens (no user context).
	Roles []string
}

type TokenServiceInterface interface {
	CreateToken(ctx context.Context, opts CreateTokenOptions, claims jwt.Claims) (*Token, error)
	BuildToken(token *Token) error
	GenerateTokenPair(ctx context.Context, clientID, userID, scope string, tokenTTL time.Duration, sessionID string) (*api.TokenResponse, error)
	GenerateTokenPairWithFamily(ctx context.Context, clientID, userID, scope string, tokenTTL time.Duration, family string, nonce string, authTime time.Time) (*api.TokenResponse, error)
	GenerateIDToken(ctx context.Context, userID, clientID, nonce, sessionID string, authTime time.Time, scope string) (string, error)
	ValidateAccessToken(ctx context.Context, tokenValue string) (*Token, error)
	RevokeToken(ctx context.Context, token string) error
	GetRefreshTokenInfo(ctx context.Context, tokenValue string) (*TokenInfo, error)
	GetAccessTokenInfo(ctx context.Context, tokenValue string) (*TokenInfo, error)
	ValidateIDToken(ctx context.Context, tokenValue string) (map[string]interface{}, error)
}

//go:generate go run go.uber.org/mock/mockgen@latest -source=$GOFILE -destination=mocks/mock_token_service.go -package=mock_domain TokenServiceInterface
