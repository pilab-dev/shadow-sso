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
	// Audience, when non-empty, is emitted as the `aud` claim instead of the
	// default (the requesting client's ID). Use this to mint tokens for a
	// specific resource, e.g. "kubernetes" for kube-apiserver OIDC.
	Audience []string
	// Subject, when non-empty, is emitted as the `sub` claim instead of
	// UserID. client_credentials tokens have no end user, so callers set this
	// to the client identity (e.g. the service account email) to produce a
	// non-empty, stable subject. kube-apiserver rejects tokens without one.
	Subject string
	// Groups, when non-empty, is emitted as the `groups` claim: a flat array
	// of strings that Kubernetes maps to RBAC group bindings via
	// --oidc-groups-claim.
	Groups []string
	// Family links a refresh token to its rotation chain.
	Family string
	// ParentJTI is the ID of the refresh token this token replaces.
	ParentJTI string
	// CnfJKT is the DPoP JWK thumbprint to bind the token to (Phase 4).
	CnfJKT string
}

type TokenServiceInterface interface {
	CreateToken(ctx context.Context, opts CreateTokenOptions, claims jwt.Claims) (*Token, error)
	BuildToken(token *Token) error
	GenerateTokenPair(ctx context.Context, clientID, userID, scope string, tokenTTL time.Duration, sessionID string) (*api.TokenResponse, error)
	GenerateTokenPairWithFamily(ctx context.Context, clientID, userID, scope string, tokenTTL time.Duration, family string, nonce string, authTime time.Time) (*api.TokenResponse, error)
	// GenerateTokenPairWithSession issues a rotated token pair that keeps the
	// session (`sid`) and refresh family, linking the new refresh token to the
	// one it replaces. Used by the refresh grant.
	GenerateTokenPairWithSession(ctx context.Context, clientID, userID, scope string, tokenTTL time.Duration, sessionID, family, parentJTI string) (*api.TokenResponse, error)
	GenerateIDToken(ctx context.Context, userID, clientID, nonce, sessionID string, authTime time.Time, scope string) (string, error)
	ValidateAccessToken(ctx context.Context, tokenValue string) (*Token, error)
	RevokeToken(ctx context.Context, token string) error
	GetRefreshTokenInfo(ctx context.Context, tokenValue string) (*TokenInfo, error)
	GetAccessTokenInfo(ctx context.Context, tokenValue string) (*TokenInfo, error)
	ValidateIDToken(ctx context.Context, tokenValue string) (map[string]interface{}, error)
}

//go:generate go run go.uber.org/mock/mockgen@latest -source=$GOFILE -destination=mocks/mock_token_service.go -package=mock_domain TokenServiceInterface
