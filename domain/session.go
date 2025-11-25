package domain

import "time"

// Session represents an active user session.
// This could be stored in Redis for quick access and MongoDB for longer-term audit if needed.
type Session struct {
	ID           string    `bson:"_id,omitempty"`      // Session ID (could be the JWT JTI)
	UserID       string    `bson:"user_id"`
	TokenID      string    `bson:"token_id,unique"`    // Corresponds to JTI of the JWT
	RefreshToken string    `bson:"refresh_token,omitempty,unique"` // If using refresh tokens
	UserAgent    string    `bson:"user_agent,omitempty"`
	IPAddress    string    `bson:"ip_address,omitempty"`
	ExpiresAt    time.Time `bson:"expires_at"`
	CreatedAt    time.Time `bson:"created_at"`
	LastUsedAt   time.Time `bson:"last_used_at,omitempty"` // Added LastUsedAt
	IsRevoked    bool      `bson:"is_revoked,omitempty"` // To mark session as logged out
}

// LoginFlowState holds the parameters and state for an OIDC authorization flow
// that requires user authentication via the separate UI.
type LoginFlowState struct {
	FlowID              string // Unique ID for this flow
	ClientID            string
	RedirectURI         string
	Scope               string
	State               string // Client's state parameter
	Nonce               string // Optional nonce from client
	CodeChallenge       string
	CodeChallengeMethod string
	UserID              string            // Populated after successful user authentication
	UserAuthenticatedAt time.Time         // Time of user authentication for this flow
	ExpiresAt           time.Time         // When this flow state should be considered invalid
	OriginalOIDCParams  map[string]string // Store other original parameters if needed
}

// UserSession represents an active user session within the OIDC provider itself.
// This indicates that the user has logged into the provider.
type UserSession struct {
	SessionID       string    // Secure random string, stored in the user's cookie
	UserID          string    // ID of the authenticated user
	AuthenticatedAt time.Time // When this session was initiated
	ExpiresAt       time.Time // When this session expires
	UserAgent       string    // Optional: User-Agent of the client
	IPAddress       string    // Optional: IP address of the client
}
