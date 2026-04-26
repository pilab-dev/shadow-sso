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
	FlowID              string            `bson:"_id,omitempty"`       // Unique ID for this flow
	ClientID            string            `bson:"client_id"`            //
	RedirectURI         string            `bson:"redirect_uri"`         //
	Scope               string            `bson:"scope"`                //
	State               string            `bson:"state"`                // Client's state parameter
	Nonce               string            `bson:"nonce,omitempty"`      // Optional nonce from client
	CodeChallenge       string            `bson:"code_challenge"`       //
	CodeChallengeMethod string            `bson:"code_challenge_method"` //
	UserID              string            `bson:"user_id"`              // Populated after successful user authentication
	UserAuthenticatedAt time.Time         `bson:"user_authenticated_at,omitempty"` // Time of user authentication for this flow
	ExpiresAt           time.Time         `bson:"expires_at"`           // When this flow state should be considered invalid
	OriginalOIDCParams  map[string]string `bson:"original_oidc_params"` // Store other original parameters if needed
}

// UserSession represents an active user session within the OIDC provider itself.
// This indicates that the user has logged into the provider.
type UserSession struct {
	SessionID       string    `bson:"_id,omitempty"`     // Secure random string, stored in the user's cookie
	UserID          string    `bson:"user_id"`            // ID of the authenticated user
	AuthenticatedAt time.Time `bson:"authenticated_at"`   // When this session was initiated
	ExpiresAt       time.Time `bson:"expires_at"`         // When this session expires
	UserAgent       string    `bson:"user_agent,omitempty"` // Optional: User-Agent of the client
	IPAddress       string    `bson:"ip_address,omitempty"` // Optional: IP address of the client
}
