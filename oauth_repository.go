package api

import "time"

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

// OAuthRepository defines the interface for OAuth 2.0 data operations
type OAuthRepository interface {
	// Client Operations
	CreateClient(client *Client) error
	GetClient(clientID string) (*Client, error)
	ValidateClient(clientID, clientSecret string) error
	UpdateClient(client *Client) error
	DeleteClient(clientID string) error

	// Authorization Code Operations
	SaveAuthCode(code *AuthCode) error
	GetAuthCode(code string) (*AuthCode, error)
	MarkAuthCodeAsUsed(code string) error
	DeleteExpiredAuthCodes() error

	// Token Operations
	StoreToken(token *Token) error
	GetAccessToken(tokenValue string) (*Token, error)
	GetRefreshToken(tokenValue string) (*Token, error)
	GetRefreshTokenInfo(tokenValue string) (*TokenInfo, error)
	GetAccessTokenInfo(tokenValue string) (*TokenInfo, error)
	RevokeToken(tokenValue string) error
	RevokeRefreshToken(tokenValue string) error
	RevokeAllUserTokens(userID string) error
	RevokeAllClientTokens(clientID string) error
	DeleteExpiredTokens() error
	ValidateAccessToken(token string) (string, error)

	// Token Introspection (RFC 7662)
	GetTokenInfo(tokenValue string) (*Token, error)

	// User Operations
	GetUserInfo(userID string) (map[string]interface{}, error)

	// Session Operations
	CreateSession(userID string, session *Session) error
	GetUserSessions(userID string) ([]Session, error)
	GetSessionByToken(token string) (*Session, error)
	UpdateSessionLastUsed(sessionID string) error
	RevokeSession(sessionID string) error
	DeleteExpiredSessions(userID string) error

	// PKCE methods
	SaveCodeChallenge(code, challenge string) error
	GetCodeChallenge(code string) (string, error)
	DeleteCodeChallenge(code string) error
}

// TokenStore represents the interface for token caching
type TokenStore interface {
	// Token Cache Operations
	Set(token *Token) error
	Get(tokenValue string) (*Token, bool)
	Delete(tokenValue string) error
	Clear() error

	// Maintenance Operations
	DeleteExpired() error
	Count() int
	Close() error
}
