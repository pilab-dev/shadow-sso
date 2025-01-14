package ssso

import (
	"context"
	"io"
	"time"
)

// AuthCode represents an OAuth 2.0 authorization code
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

// TokenInfo represents metadata about a token
type TokenInfo struct {
	ID        string    `json:"id"`         // Unique token identifier
	TokenType string    `json:"token_type"` // "access_token" or "refresh_token"
	ClientID  string    `json:"client_id"`  // Client that the token was issued to
	UserID    string    `json:"user_id"`    // User that authorized the token
	Scope     string    `json:"scope"`      // Authorized scopes
	IssuedAt  time.Time `json:"issued_at"`  // When the token was issued
	ExpiresAt time.Time `json:"expires_at"` // When the token expires
	IsRevoked bool      `json:"is_revoked"` // Whether token has been revoked
}

// Client represents an OAuth 2.0 client application
type Client struct {
	ID           string    `json:"id"`            // Unique client identifier
	Secret       string    `json:"-"`             // Client secret (hashed)
	Name         string    `json:"name"`          // Client application name
	RedirectURIs []string  `json:"redirect_uris"` // Allowed redirect URIs
	GrantTypes   []string  `json:"grant_types"`   // Allowed grant types
	Scopes       []string  `json:"scopes"`        // Allowed scopes
	CreatedAt    time.Time `json:"created_at"`    // Creation timestamp
	UpdatedAt    time.Time `json:"updated_at"`    // Last update timestamp
}

// Token represents an OAuth 2.0 token (access or refresh)
type Token struct {
	ID         string    `json:"id"`           // Unique token identifier
	TokenType  string    `json:"token_type"`   // "access_token" or "refresh_token"
	TokenValue string    `json:"token_value"`  // The actual token string
	ClientID   string    `json:"client_id"`    // Client that requested the token
	UserID     string    `json:"user_id"`      // User who authorized the token
	Scope      string    `json:"scope"`        // Authorized scopes
	ExpiresAt  time.Time `json:"expires_at"`   // Expiration timestamp
	IsRevoked  bool      `json:"is_revoked"`   // Whether token is revoked
	CreatedAt  time.Time `json:"created_at"`   // Creation timestamp
	LastUsedAt time.Time `json:"last_used_at"` // Last usage timestamp
}

// OAuthRepository defines the interface for OAuth 2.0 data operations.
// This interface provides a comprehensive set of methods to manage OAuth 2.0 entities
// including clients, authorization codes, tokens, sessions, and PKCE challenges.
type OAuthRepository interface {
	io.Closer

	// Client Operations

	// CreateClient creates a new OAuth client in the repository.
	// Returns an error if the client already exists or if there's a database error.
	CreateClient(ctx context.Context, client *Client) error

	// GetClient retrieves a client by its client ID.
	// Returns the client if found, or an error if not found or if there's a database error.
	GetClient(ctx context.Context, clientID string) (*Client, error)

	// ValidateClient verifies if the provided client credentials (ID and secret) are valid.
	// Returns nil if valid, or an error if invalid credentials or database error.
	ValidateClient(ctx context.Context, clientID, clientSecret string) error

	// UpdateClient updates an existing OAuth client's information.
	// Returns an error if the client doesn't exist or if there's a database error.
	UpdateClient(ctx context.Context, client *Client) error

	// DeleteClient removes a client and all associated data from the repository.
	// Returns an error if the client doesn't exist or if there's a database error.
	DeleteClient(ctx context.Context, clientID string) error

	// Authorization Code Operations

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

	// Session Operations

	// CreateSession creates a new user session.
	// Returns an error if the session already exists or if there's a database error.
	CreateSession(ctx context.Context, userID string, session *UserSession) error

	// GetUserSessions retrieves all active sessions for a user.
	// Returns a slice of sessions if found, or an error if not found or database error.
	GetUserSessions(ctx context.Context, userID string) ([]UserSession, error)

	// GetSessionByToken retrieves a session by its associated token.
	// Returns the session if found, or an error if not found or database error.
	GetSessionByToken(ctx context.Context, token string) (*UserSession, error)

	// UpdateSessionLastUsed updates the last used timestamp of a session.
	// Returns an error if the session doesn't exist or if there's a database error.
	UpdateSessionLastUsed(ctx context.Context, sessionID string) error

	// RevokeSession invalidates a specific session.
	// Returns an error if the session doesn't exist or if there's a database error.
	RevokeSession(ctx context.Context, sessionID string) error

	// DeleteExpiredSessions removes all expired sessions for a user.
	// Returns an error if there's a database error during cleanup.
	DeleteExpiredSessions(ctx context.Context, userID string) error

	// PKCE methods

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

// TokenStore represents the interface for token caching operations.
// This interface provides methods to manage a temporary token cache for improved performance.
type TokenStore interface {
	// Token Cache Operations

	// Set stores a token in the cache.
	// Returns an error if the operation fails.
	Set(token *Token) error

	// Get retrieves a token from the cache by its value.
	// Returns the token and true if found, or nil and false if not found.
	Get(tokenValue string) (*Token, bool)

	// Delete removes a token from the cache.
	// Returns an error if the operation fails.
	Delete(tokenValue string) error

	// Clear removes all tokens from the cache.
	// Returns an error if the operation fails.
	Clear() error

	// Maintenance Operations

	// DeleteExpired removes all expired tokens from the cache.
	// Returns an error if the operation fails.
	DeleteExpired() error

	// Count returns the number of tokens currently in the cache.
	Count() int

	// Close releases any resources used by the token store.
	// Returns an error if the operation fails.
	Close() error
}
