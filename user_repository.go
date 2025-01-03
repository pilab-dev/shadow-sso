package sso

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"time"
)

// UserSession represents a user's login session
type UserSession struct {
	ID           string    `json:"id"`            // Unique session identifier
	UserID       string    `json:"user_id"`       // User ID
	AccessToken  string    `json:"access_token"`  // Current access token
	RefreshToken string    `json:"refresh_token"` // Current refresh token
	ExpiresAt    time.Time `json:"expires_at"`    // Session expiration
	CreatedAt    time.Time `json:"created_at"`    // When session was created
	LastUsedAt   time.Time `json:"last_used_at"`  // Last activity timestamp
	DeviceInfo   string    `json:"device_info"`   // Client device information
	IsRevoked    bool      `json:"is_revoked"`    // Whether session is revoked
}

// User represents a registered user in the system
type User struct {
	// Unique identifier for the user
	ID string
	// Username used for authentication
	Username string
	// Hashed password for authentication
	Password string
	// Time when the user account was created
	CreatedAt time.Time
	// Time when the user account was last updated
	UpdatedAt time.Time
}

// UserRepository defines the interface for user-related data operations
type UserRepository interface {
	// CreateUser creates a new user with the given username and password
	// Returns the created user or an error if creation fails
	CreateUser(username, password string) (*User, error)

	// GetUserByID retrieves a user by their unique ID
	// Returns the user or an error if not found
	GetUserByID(id string) (*User, error)

	// GetUserByUsername retrieves a user by their username
	// Returns the user or an error if not found
	GetUserByUsername(username string) (*User, error)

	// UpdateUser updates an existing user's information
	// Returns an error if the update fails
	UpdateUser(user *User) error

	// DeleteUser removes a user by their ID
	// Returns an error if deletion fails
	DeleteUser(id string) error

	// CreateSession creates a new session for the given user
	// Returns an error if session creation fails
	CreateSession(userID string, session *UserSession) error

	// GetUserSessions retrieves all active sessions for a user
	// Returns a slice of sessions or an error if retrieval fails
	GetUserSessions(userID string) ([]UserSession, error)

	// GetSessionByToken retrieves a session by its access token
	// Returns the session or an error if not found
	GetSessionByToken(accessToken string) (*UserSession, error)

	// UpdateSessionLastUsed updates the LastUsedAt timestamp of a session
	// Returns an error if the update fails
	UpdateSessionLastUsed(sessionID string) error

	// RevokeSession marks a session as revoked
	// Returns an error if the revocation fails
	RevokeSession(sessionID string) error

	// DeleteExpiredSessions removes all expired sessions for a user
	// Returns an error if the deletion fails
	DeleteExpiredSessions(userID string) error
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
func (s *PKCEService) ValidatePKCE(code string, codeVerifier string) error {
	// Validate inputs
	if code == "" || codeVerifier == "" {
		return fmt.Errorf("code and code verifier are required")
	}

	// Get stored auth code
	authCode, err := s.oauthRepo.GetAuthCode(code)
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
