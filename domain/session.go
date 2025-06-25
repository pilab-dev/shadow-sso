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
