package domain

import (
	"context"
	"time"

	"github.com/pilab-dev/shadow-sso/api"
)

//go:generate go run go.uber.org/mock/mockgen@latest -source=$GOFILE -destination=mocks/mock_oauth_service.go -package=mock_domain OAuthServiceInterface

type OAuthServiceInterface interface {
	RegisterUser(ctx context.Context, username, password string) (*User, error)
	Login(ctx context.Context, username, password, deviceInfo string) (*api.TokenResponse, error)
	GetUserSessions(ctx context.Context, userID string) ([]*Session, error)
	RefreshToken(ctx context.Context, refreshTokenValue string, clientID string) (*api.TokenResponse, error)
	GetJWKS() *JWKS
	ValidateClient(ctx context.Context, clientID, clientSecret string) (*Client, error)
	DirectGrant(ctx context.Context, clientID, clientSecret, username, password, scope string) (*api.TokenResponse, error)
	ClientCredentials(ctx context.Context, clientID, clientSecret, scope string) (*api.TokenResponse, error)
	PasswordGrant(ctx context.Context, username, password, scope string, cli *Client) (*api.TokenResponse, error)
	ExchangeAuthorizationCode(ctx context.Context, code, clientID, clientSecret, redirectURI string) (*api.TokenResponse, error)
	IntrospectToken(ctx context.Context, token, tokenTypeHint, clientID, clientSecret string) (*TokenIntrospection, error)
	RevokeToken(ctx context.Context, tokenToRevoke, tokenTypeHint, clientID, clientSecret string) error
	GenerateAuthCode(ctx context.Context, clientID, userID, redirectURI, scope, codeChallenge, codeChallengeMethod, nonce string, authTime time.Time) (string, error)
	InitiateDeviceAuthorization(ctx context.Context, clientID, scope, verificationBaseURI string) (*api.DeviceAuthResponse, error)
	VerifyUserCode(ctx context.Context, userCode, userID string) (*DeviceCode, error)
	IssueTokenForDeviceFlow(ctx context.Context, deviceCode, clientID string) (*api.TokenResponse, error)
	TokenExchange(ctx context.Context, subjectToken, subjectTokenType, requestedTokenType, resource, scope, clientID string) (*api.TokenResponse, error)
}
