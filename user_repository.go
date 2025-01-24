package ssso

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"time"
)

// UserSession represents a user's login session
type UserSession struct {
	ID           string    `bson:"id"            json:"id"`           // Unique session identifier
	UserID       string    `bson:"user_id"       json:"userId"`       // User ID
	AccessToken  string    `bson:"access_token"  json:"accessToken"`  // Current access token
	RefreshToken string    `bson:"refresh_token" json:"refreshToken"` // Current refresh token
	ExpiresAt    time.Time `bson:"expires_at"    json:"expiresAt"`    // Session expiration
	CreatedAt    time.Time `bson:"created_at"    json:"createdAt"`    // When session was created
	LastUsedAt   time.Time `bson:"last_used_at"  json:"lastUsedAt"`   // Last activity timestamp
	DeviceInfo   string    `bson:"device_info"   json:"deviceInfo"`   // Client device information
	IsRevoked    bool      `bson:"is_revoked"    json:"isRevoked"`    // Whether session is revoked
	Scope        string    `bson:"scope"         json:"scope"`        // ? Requested scope - is this needed? or a good place to store this?
}

// User represents a registered user in the system
type User struct {
	// Unique identifier for the user
	ID string `bson:"_id" json:"id"`
	// Username used for authentication
	Username string `bson:"username" json:"username"`
	// Password is a hashed password for authentication
	Password string `bson:"password" json:"password"`
	// Time when the user account was created
	CreatedAt time.Time `bson:"created_at" json:"createdAt"`
	// Time when the user account was last updated
	UpdatedAt time.Time `bson:"updated_at" json:"updatedAt"`
}

// UserStore defines the interface for user-related data operations
type UserStore interface {
	// CreateUser creates a new user with the given username and password
	// Returns the created user or an error if creation fails
	CreateUser(ctx context.Context, username, password string) (*User, error)

	// GetUserByID retrieves a user by their unique ID
	// Returns the user or an error if not found
	GetUserByID(ctx context.Context, id string) (*User, error)

	// GetUserByUsername retrieves a user by their username
	// Returns the user or an error if not found
	GetUserByUsername(ctx context.Context, username string) (*User, error)

	// UpdateUser updates an existing user's information
	// Returns an error if the update fails
	UpdateUser(ctx context.Context, user *User) error

	// DeleteUser removes a user by their ID
	// Returns an error if deletion fails
	DeleteUser(ctx context.Context, id string) error

	// UserSessionRepository defines the interface for user session-related data operations
	// ! TODO: Temporary we are embedding, but should be a separate interface
	UserSessionStore
}

// UserSessionStore defines the interface for user session-related data operations.
type UserSessionStore interface {
	// CreateSession creates a new session for the given user
	// Returns an error if session creation fails
	CreateSession(ctx context.Context, userID string, session *UserSession) error

	// GetUserSessions retrieves all active sessions for a user
	// Returns a slice of sessions or an error if retrieval fails
	GetUserSessions(ctx context.Context, userID string) ([]UserSession, error)

	// GetSessionByToken retrieves a session by its access token
	// Returns the session or an error if not found
	GetSessionByToken(ctx context.Context, accessToken string) (*UserSession, error)

	// UpdateSessionLastUsed updates the LastUsedAt timestamp of a session
	// Returns an error if the update fails
	UpdateSessionLastUsed(ctx context.Context, sessionID string) error

	// RevokeSession marks a session as revoked
	// Returns an error if the revocation fails
	RevokeSession(ctx context.Context, sessionID string) error

	// DeleteExpiredSessions removes all expired sessions for a user
	// Returns an error if the deletion fails
	DeleteExpiredSessions(ctx context.Context, userID string) error
}

// PKCEParams represents PKCE parameters
type PKCEParams struct {
	CodeChallenge       string
	CodeChallengeMethod string
}

// ValidatePKCE validates the PKCE code verifier against the stored code challenge
// code: The authorization code to validate
// codeVerifier: The PKCE code verifier provided by the client
// Returns error if validation fails
func (s *PKCEService) ValidatePKCE(ctx context.Context, code string, codeVerifier string) error {
	// Validate inputs
	if code == "" || codeVerifier == "" {
		return fmt.Errorf("code and code verifier are required")
	}

	// Get stored auth code
	authCode, err := s.oauthRepo.GetAuthCode(ctx, code)
	if err != nil {
		return fmt.Errorf("invalid auth code: %w", err)
	}

	// Check if PKCE was used
	if authCode.CodeChallenge == "" {
		return fmt.Errorf("PKCE required but not provided in original request")
	}

	// Validate code verifier length (RFC 7636 Section 4.1)
	if len(codeVerifier) < 43 || len(codeVerifier) > 128 {
		return fmt.Errorf("code verifier must be between 43 and 128 characters")
	}

	// Compute challenge based on method
	var computedChallenge string
	switch authCode.CodeChallengeMethod {
	case "S256":
		h := sha256.New()
		h.Write([]byte(codeVerifier))
		computedChallenge = base64.RawURLEncoding.EncodeToString(h.Sum(nil))
	case "plain":
		computedChallenge = codeVerifier
	default:
		return fmt.Errorf("unsupported code challenge method: %s", authCode.CodeChallengeMethod)
	}

	// Constant time comparison to prevent timing attacks
	if subtle.ConstantTimeCompare([]byte(computedChallenge), []byte(authCode.CodeChallenge)) != 1 {
		return fmt.Errorf("code verifier does not match challenge")
	}

	return nil
}
