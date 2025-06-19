//nolint:tagliatelle
package ssso

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
type TokenRepository interface {
	// Token Operations

	// StoreToken saves a new access or refresh token in the repository.
	// Returns an error if the token already exists or if there's a database error.
	StoreToken(ctx context.Context, token *Token) error

	// GetAccessToken retrieves an access token by its value.
	// Returns the token if found, or an error if not found or database error.
	GetAccessToken(ctx context.Context, tokenValue string) (*Token, error)

	// GetRefreshToken retrieves a refresh token by its value.
	// Returns the token if found, or an error if not found or database error.
	GetRefreshToken(ctx context.Context, tokenValue string) (*Token, error)

	// GetRefreshTokenInfo retrieves metadata about a refresh token.
	// Returns the token info if found, or an error if not found or database error.
	GetRefreshTokenInfo(ctx context.Context, tokenValue string) (*TokenInfo, error)

	// GetAccessTokenInfo retrieves metadata about an access token.
	// Returns the token info if found, or an error if not found or database error.
	GetAccessTokenInfo(ctx context.Context, tokenValue string) (*TokenInfo, error)

	// RevokeToken invalidates an access token.
	// Returns an error if the token doesn't exist or if there's a database error.
	RevokeToken(ctx context.Context, tokenValue string) error

	// RevokeRefreshToken invalidates a refresh token.
	// Returns an error if the token doesn't exist or if there's a database error.
	RevokeRefreshToken(ctx context.Context, tokenValue string) error

	// RevokeAllUserTokens invalidates all tokens associated with a user.
	// Returns an error if there's a database error during revocation.
	RevokeAllUserTokens(ctx context.Context, userID string) error

	// RevokeAllClientTokens invalidates all tokens associated with a client.
	// Returns an error if there's a database error during revocation.
	RevokeAllClientTokens(ctx context.Context, clientID string) error

	// DeleteExpiredTokens removes all expired tokens from the repository.
	// Returns an error if there's a database error during cleanup.
	DeleteExpiredTokens(ctx context.Context) error

	// ValidateAccessToken verifies if an access token is valid and returns the associated user ID.
	// Returns the user ID if valid, or an error if invalid or database error.
	ValidateAccessToken(ctx context.Context, token string) (string, error)

	// Token Introspection (RFC 7662)

	// GetTokenInfo retrieves detailed information about a token as per RFC 7662.
	// Returns the token information if found, or an error if not found or database error.
	GetTokenInfo(ctx context.Context, tokenValue string) (*Token, error)
}

// AuthorizationCodeRepository defines the interface for OAuth 2.0 authorization code operations.
type AuthorizationCodeRepository interface {
	// SaveAuthCode stores a new authorization code in the repository.
	// Returns an error if the code already exists or if there's a database error.
	SaveAuthCode(ctx context.Context, code *AuthCode) error

	// GetAuthCode retrieves an authorization code by its value.
	// Returns the authorization code if found, or an error if not found or database error.
	GetAuthCode(ctx context.Context, code string) (*AuthCode, error)

	// MarkAuthCodeAsUsed marks an authorization code as used to prevent replay attacks.
	// Returns an error if the code doesn't exist or if there's a database error.
	MarkAuthCodeAsUsed(ctx context.Context, code string) error

	// DeleteExpiredAuthCodes removes all expired authorization codes from the repository.
	// Returns an error if there's a database error during cleanup.
	DeleteExpiredAuthCodes(ctx context.Context) error
}

// // SessionRepository defines the interface for OAuth 2.0 session operations.
// type SessionRepository interface {
// 	// CreateSession creates a new user session.
// 	// Returns an error if the session already exists or if there's a database error.
// 	CreateSession(ctx context.Context, userID string, session *UserSession) error

// 	// GetUserSessions retrieves all active sessions for a user.
// 	// Returns a slice of sessions if found, or an error if not found or database error.
// 	GetUserSessions(ctx context.Context, userID string) ([]UserSession, error)

// 	// GetSessionByToken retrieves a session by its associated token.
// 	// Returns the session if found, or an error if not found or database error.
// 	GetSessionByToken(ctx context.Context, token string) (*UserSession, error)

// 	// UpdateSessionLastUsed updates the last used timestamp of a session.
// 	// Returns an error if the session doesn't exist or if there's a database error.
// 	UpdateSessionLastUsed(ctx context.Context, sessionID string) error

// 	// RevokeSession invalidates a specific session.
// 	// Returns an error if the session doesn't exist or if there's a database error.
// 	RevokeSession(ctx context.Context, sessionID string) error

// 	// DeleteExpiredSessions removes all expired sessions for a user.
// 	// Returns an error if there's a database error during cleanup.
// 	DeleteExpiredSessions(ctx context.Context, userID string) error
// }

// PkceRepository defines the interface for OAuth 2.0 PKCE operations.
type PkceRepository interface {
	// SaveCodeChallenge stores a PKCE code challenge for a given authorization code.
	// Returns an error if the challenge already exists or if there's a database error.
	SaveCodeChallenge(ctx context.Context, code, challenge string) error

	// GetCodeChallenge retrieves a PKCE code challenge for verification.
	// Returns the challenge if found, or an error if not found or database error.
	GetCodeChallenge(ctx context.Context, code string) (string, error)

	// DeleteCodeChallenge removes a PKCE code challenge after use.
	// Returns an error if the challenge doesn't exist or if there's a database error.
	DeleteCodeChallenge(ctx context.Context, code string) error
}

// DeviceAuthorizationRepository defines methods for managing device authorization flow data.
type DeviceAuthorizationRepository interface {
	SaveDeviceAuth(ctx context.Context, auth *DeviceCode) error
	GetDeviceAuthByDeviceCode(ctx context.Context, deviceCode string) (*DeviceCode, error)
	GetDeviceAuthByUserCode(ctx context.Context, userCode string) (*DeviceCode, error)
	ApproveDeviceAuth(ctx context.Context, userCode string, userID string) (*DeviceCode, error)
	UpdateDeviceAuthStatus(ctx context.Context, deviceCode string, status DeviceCodeStatus) error
	UpdateDeviceAuthLastPolledAt(ctx context.Context, deviceCode string) error
	DeleteExpiredDeviceAuths(ctx context.Context) error // For cleanup
}

// OAuthRepository defines the interface for OAuth 2.0 data operations.
type OAuthRepository interface {
	io.Closer

	// Client methods
	CreateClient(ctx context.Context, c *client.Client) error               // Changed to client.Client
	GetClient(ctx context.Context, clientID string) (*client.Client, error) // Changed to client.Client
	UpdateClient(ctx context.Context, c *client.Client) error               // Changed to client.Client
	DeleteClient(ctx context.Context, clientID string) error
	ListClients(ctx context.Context, pageSize int32, pageToken string) ([]*client.Client, string, error) // Changed to client.Client
	ValidateClient(ctx context.Context, clientID, clientSecret string) error                             // Added from mongo_oauth_repository method list

	AuthorizationCodeRepository
	TokenRepository // Uncommented and included
	// SessionRepository // Keep commented for now, as it's a separate domain interface
	// SessionRepository // Assuming this will be added or is part of a larger refactor not in scope
	PkceRepository
	DeviceAuthorizationRepository // Embed the new interface
}
