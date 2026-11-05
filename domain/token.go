package domain

import "time"

const (
	TokenTypeAccessToken  = "access_token"
	TokenTypeRefreshToken = "refresh_token"
)

// TokenInfo represents metadata about a token.
type TokenInfo struct {
	ID                 string     `bson:"_id"        json:"id"`         // Unique token identifier
	TokenType          string     `bson:"token_type" json:"token_type"` // "access_token" or "refresh_token"
	ClientID           string     `bson:"client_id"  json:"client_id"`  // Client that the token was issued to
	UserID             string     `bson:"user_id"    json:"user_id"`    // User that authorized the token
	Scope              string     `bson:"scope"      json:"scope"`      // Authorized scopes
	IssuedAt           time.Time  `bson:"issued_at"  json:"issued_at"`  // When the token was issued
	ExpiresAt          time.Time  `bson:"expires_at" json:"expires_at"` // When the token expires
	IsRevoked          bool       `bson:"is_revoked" json:"is_revoked"` // Whether token has been revoked
	Roles              []string   `bson:"roles"      json:"roles"`
	RefreshTokenFamily string     `bson:"refresh_token_family" json:"refresh_token_family"` // For token refresh families
	SessionID          string     `bson:"session_id,omitempty" json:"session_id,omitempty"` // `sid` claim: the session this token belongs to
	UsedAt             *time.Time `bson:"used_at,omitempty" json:"used_at,omitempty"`       // Set when a refresh token was rotated; a second use is replay
	CnfJKT             string     `bson:"cnf_jkt,omitempty" json:"cnf_jkt,omitempty"`       // DPoP binding thumbprint
	// AuthorizationDetails is the RFC 9396 authorization_details JSON array granted to the token.
	AuthorizationDetails string `bson:"authorization_details,omitempty" json:"authorization_details,omitempty"`
}

// Token represents an OAuth token, also used for synthetic service account tokens.
type Token struct {
	ID         string    `bson:"_id,omitempty" json:"id"`
	TokenType  string    `bson:"token_type" json:"token_type"`
	TokenValue string    `bson:"token_value" json:"token_value"`
	ClientID   string    `bson:"client_id" json:"client_id"`
	UserID     string    `bson:"user_id" json:"user_id"` // For SA JWT, this will be the 'iss' (client_email)
	Scope      string    `bson:"scope,omitempty" json:"scope,omitempty"`
	ExpiresAt  time.Time `bson:"expires_at" json:"expires_at"`
	CreatedAt  time.Time `bson:"created_at" json:"created_at"`
	LastUsedAt time.Time `bson:"last_used_at" json:"last_used_at"`
	IsRevoked  bool      `bson:"is_revoked" json:"is_revoked"`
	Issuer     string    `bson:"issuer,omitempty" json:"issuer,omitempty"`
	Roles      []string  `bson:"roles,omitempty" json:"roles,omitempty"`
	SessionID  string    `bson:"session_id,omitempty" json:"session_id,omitempty"`
	// Audience mirrors the `aud` claim when it differs from ClientID.
	Audience []string `bson:"audience,omitempty" json:"audience,omitempty"`
	// Subject mirrors the `sub` claim when it differs from UserID (e.g.
	// client_credentials tokens, which have no end user).
	Subject string `bson:"subject,omitempty" json:"subject,omitempty"`
	// Groups mirrors the `groups` claim used for Kubernetes RBAC mapping.
	Groups []string `bson:"groups,omitempty" json:"groups,omitempty"`
	// Family links a refresh token to its rotation chain. The whole family is
	// revoked when a used token is replayed.
	Family string `bson:"family,omitempty" json:"family,omitempty"`
	// ParentJTI is the ID of the refresh token this one replaced.
	ParentJTI string `bson:"parent_jti,omitempty" json:"parent_jti,omitempty"`
	// UsedAt is set when the refresh token was exchanged. A token with UsedAt
	// set that is presented again indicates replay.
	UsedAt *time.Time `bson:"used_at,omitempty" json:"used_at,omitempty"`
	// RotatedTo is the ID of the refresh token issued in exchange.
	RotatedTo string `bson:"rotated_to,omitempty" json:"rotated_to,omitempty"`
	// ExpiryAuditedAt is set once the expiry sweeper has emitted a
	// TokenExpired audit event, so it does not repeat every interval.
	ExpiryAuditedAt *time.Time `bson:"expiry_audited_at,omitempty" json:"expiry_audited_at,omitempty"`
	// TokenHash is the SHA-256 hash of the raw refresh token value, used so
	// refresh tokens are never stored in replayable form at rest.
	TokenHash string `bson:"token_hash,omitempty" json:"token_hash,omitempty"`
	// CnfJKT is the JWK thumbprint the token is bound to (DPoP, Phase 4).
	CnfJKT string `bson:"cnf_jkt,omitempty" json:"cnf_jkt,omitempty"`
	// AuthorizationDetails is the RFC 9396 authorization_details JSON array granted to the token.
	AuthorizationDetails string `bson:"authorization_details,omitempty" json:"authorization_details,omitempty"`
}
