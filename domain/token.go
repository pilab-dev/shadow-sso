package domain

import "time"

const (
	TokenTypeAccessToken  = "access_token"
	TokenTypeRefreshToken = "refresh_token"
)

// TokenInfo represents metadata about a token.
type TokenInfo struct {
	ID        string    `bson:"_id"        json:"id"`
	TokenType string    `bson:"token_type" json:"token_type"`
	ClientID  string    `bson:"client_id"  json:"client_id"`
	UserID    string    `bson:"user_id"    json:"user_id"`
	Scope     string    `bson:"scope"      json:"scope"`
	IssuedAt  time.Time `bson:"issued_at"  json:"issued_at"`
	ExpiresAt time.Time `bson:"expires_at" json:"expires_at"`
	IsRevoked bool      `bson:"is_revoked" json:"is_revoked"`
	Roles     []string  `bson:"roles"      json:"roles"`

	RefreshTokenFamily string `bson:"refresh_token_family,omitempty" json:"-"`
}

// Token represents an OAuth token, also used for synthetic service account tokens.
type Token struct {
	ID         string    `bson:"_id,omitempty" json:"id"`
	TokenType  string    `bson:"token_type" json:"token_type"`
	TokenValue string    `bson:"token_value" json:"token_value"`
	ClientID   string    `bson:"client_id" json:"client_id"`
	UserID     string    `bson:"user_id" json:"user_id"`
	Scope      string    `bson:"scope,omitempty" json:"scope,omitempty"`
	ExpiresAt  time.Time `bson:"expires_at" json:"expires_at"`
	CreatedAt  time.Time `bson:"created_at" json:"created_at"`
	LastUsedAt time.Time `bson:"last_used_at" json:"last_used_at"`
	IsRevoked  bool      `bson:"is_revoked,omitempty" json:"is_revoked,omitempty"`
	Issuer     string    `bson:"issuer,omitempty" json:"issuer,omitempty"`
	Roles      []string  `bson:"roles,omitempty" json:"roles,omitempty"`

	RefreshTokenFamily string `bson:"refresh_token_family,omitempty" json:"-"`
}
