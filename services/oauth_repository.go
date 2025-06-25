//nolint:tagliatelle
package services

import (
	"context"
	"io"
	"time"

	"github.com/pilab-dev/shadow-sso/client"
)

// ... (keep existing structs like AuthCode, TokenInfo, Client, Token) ...

// DeviceCodeStatus represents the status of a device authorization request.
type DeviceCodeStatus string

const (
	DeviceCodeStatusPending    DeviceCodeStatus = "pending"
	DeviceCodeStatusAuthorized DeviceCodeStatus = "authorized"
	DeviceCodeStatusDenied     DeviceCodeStatus = "denied"
	DeviceCodeStatusExpired    DeviceCodeStatus = "expired"
	DeviceCodeStatusRedeemed   DeviceCodeStatus = "redeemed" // Added for when tokens have been issued
)

// DeviceCode holds the information for a device authorization grant.
type DeviceCode struct {
	ID           string           `bson:"_id" json:"id"`                  // Unique ID for the device code entry
	DeviceCode   string           `bson:"device_code" json:"device_code"` // The code the device uses to poll
	UserCode     string           `bson:"user_code" json:"user_code"`     // The code the user enters on another device
	ClientID     string           `bson:"client_id" json:"client_id"`
	Scope        string           `bson:"scope" json:"scope"`
	Status       DeviceCodeStatus `bson:"status" json:"status"`
	UserID       string           `bson:"user_id,omitempty" json:"user_id,omitempty"` // Associated user ID once authorized
	ExpiresAt    time.Time        `bson:"expires_at" json:"expires_at"`               // Expiration time for both device_code and user_code
	Interval     int              `bson:"interval" json:"interval"`                   // Polling interval for the device
	CreatedAt    time.Time        `bson:"created_at" json:"created_at"`
	LastPolledAt time.Time        `bson:"last_polled_at,omitempty" json:"last_polled_at,omitempty"` // Tracks when the device last polled
}

// AuthCode represents an OAuth 2.0 authorization code.
type AuthCode struct {
	Code        string    `json:"code"`         // Unique authorization code
	ClientID    string    `json:"client_id"`    // Client application ID
	UserID      string    `json:"user_id"`      // User who authorized the request
	RedirectURI string    `json:"redirect_uri"` // Client's callback URL
	Scope       string    `json:"scope"`        // Authorized scopes
	ExpiresAt   time.Time `json:"expires_at"`   // Expiration timestamp
	Used        bool      `json:"used"`         // Whether code has been exchanged
	CreatedAt   time.Time `json:"created_at"`   // Creation timestamp

	CodeChallenge       string `json:"code_challenge,omitempty"`
	CodeChallengeMethod string `json:"code_challenge_method,omitempty"`
}

// TokenInfo represents metadata about a token.
type TokenInfo struct {
	ID        string    `bson:"_id"        json:"id"`         // Unique token identifier
	TokenType string    `bson:"token_type" json:"token_type"` // "access_token" or "refresh_token"
	ClientID  string    `bson:"client_id"  json:"client_id"`  // Client that the token was issued to
	UserID    string    `bson:"user_id"    json:"user_id"`    // User that authorized the token
	Scope     string    `bson:"scope"      json:"scope"`      // Authorized scopes
	IssuedAt  time.Time `bson:"issued_at"  json:"issued_at"`  // When the token was issued
	ExpiresAt time.Time `bson:"expires_at" json:"expires_at"` // When the token expires
	IsRevoked bool      `bson:"is_revoked" json:"is_revoked"` // Whether token has been revoked
	Roles     []string  `bson:"roles"      json:"roles"`
}

// Client represents an OAuth 2.0 client application.
type Client struct {
	ID           string    `json:"id"`            // Unique client identifier
	Secret       string    `json:"-"`             // Client secret (hashed)
	Name         string    `json:"name"`          // Client application name
	RedirectURIs []string  `json:"redirect_uris"` // Allowed redirect URIs
	GrantTypes   []string  `json:"grant_types"`   // Allowed grant types
	Scopes       []string  `json:"scopes"`        // Allowed scopes
	CreatedAt    time.Time `json:"created_at"`    // Creation timestamp
}

// TokenRepository represents an OAuth 2.0 token repository.
//
//nolint:interfacebloat
//go:generate mockgen -source=$GOFILE -destination=../../mocks/mock_$GOPACKAGE/mock_$GOFILE -package=mock_$GOPACKAGE
type TokenRepository interface {
	StoreToken(ctx context.Context, token *Token) error
	GetAccessToken(ctx context.Context, tokenValue string) (*Token, error)
	GetRefreshToken(ctx context.Context, tokenValue string) (*Token, error)
	GetRefreshTokenInfo(ctx context.Context, tokenValue string) (*TokenInfo, error)
	GetAccessTokenInfo(ctx context.Context, tokenValue string) (*TokenInfo, error)
	RevokeToken(ctx context.Context, tokenValue string) error
	RevokeRefreshToken(ctx context.Context, tokenValue string) error
	RevokeAllUserTokens(ctx context.Context, userID string) error
	RevokeAllClientTokens(ctx context.Context, clientID string) error
	DeleteExpiredTokens(ctx context.Context) error
	ValidateAccessToken(ctx context.Context, token string) (string, error)
	GetTokenInfo(ctx context.Context, tokenValue string) (*Token, error)
}

//go:generate mockgen -source=$GOFILE -destination=../../mocks/mock_$GOPACKAGE/mock_$GOFILE -package=mock_$GOPACKAGE
type AuthorizationCodeRepository interface {
	SaveAuthCode(ctx context.Context, code *AuthCode) error
	GetAuthCode(ctx context.Context, code string) (*AuthCode, error)
	MarkAuthCodeAsUsed(ctx context.Context, code string) error
	DeleteExpiredAuthCodes(ctx context.Context) error
}

//go:generate mockgen -source=$GOFILE -destination=../../mocks/mock_$GOPACKAGE/mock_$GOFILE -package=mock_$GOPACKAGE
type PkceRepository interface {
	SaveCodeChallenge(ctx context.Context, code, challenge string) error
	GetCodeChallenge(ctx context.Context, code string) (string, error)
	DeleteCodeChallenge(ctx context.Context, code string) error
}

//go:generate mockgen -source=$GOFILE -destination=../../mocks/mock_$GOPACKAGE/mock_$GOFILE -package=mock_$GOPACKAGE
type DeviceAuthorizationRepository interface {
	SaveDeviceAuth(ctx context.Context, auth *DeviceCode) error
	GetDeviceAuthByDeviceCode(ctx context.Context, deviceCode string) (*DeviceCode, error)
	GetDeviceAuthByUserCode(ctx context.Context, userCode string) (*DeviceCode, error)
	ApproveDeviceAuth(ctx context.Context, userCode string, userID string) (*DeviceCode, error)
	UpdateDeviceAuthStatus(ctx context.Context, deviceCode string, status DeviceCodeStatus) error
	UpdateDeviceAuthLastPolledAt(ctx context.Context, deviceCode string) error
	DeleteExpiredDeviceAuths(ctx context.Context) error
}

//go:generate mockgen -source=$GOFILE -destination=../../mocks/mock_$GOPACKAGE/mock_$GOFILE -package=mock_$GOPACKAGE
type OAuthRepository interface {
	io.Closer
	CreateClient(ctx context.Context, c *client.Client) error
	GetClient(ctx context.Context, clientID string) (*client.Client, error)
	UpdateClient(ctx context.Context, c *client.Client) error
	DeleteClient(ctx context.Context, clientID string) error
	ListClients(ctx context.Context, pageSize int32, pageToken string) ([]*client.Client, string, error)
	ValidateClient(ctx context.Context, clientID, clientSecret string) error
	AuthorizationCodeRepository
	TokenRepository
	PkceRepository
	DeviceAuthorizationRepository
}
