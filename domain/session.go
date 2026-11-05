package domain

import "time"

// Session represents an active user session.
// This could be stored in Redis for quick access and MongoDB for longer-term audit if needed.
type Session struct {
	ID       string    `bson:"_id,omitempty"` // Session ID (could be the JWT JTI)
	UserID   string    `bson:"user_id"`
	ClientID string    `bson:"client_id,omitempty"` // OAuth client that created the session, when known
	AuthTime time.Time `bson:"auth_time,omitempty"`
	AMR      []string  `bson:"amr,omitempty"`
	ACR      string    `bson:"acr,omitempty"`

	// Device
	UserAgent  string `bson:"user_agent,omitempty"`
	DeviceName string `bson:"device_name,omitempty"`
	DeviceType string `bson:"device_type,omitempty"` // desktop | mobile | tablet | cli | api
	OS         string `bson:"os,omitempty"`
	Browser    string `bson:"browser,omitempty"`

	// Location (coarse only)
	IPAddress string `bson:"ip_address,omitempty"`
	IPCountry string `bson:"ip_country,omitempty"`
	IPRegion  string `bson:"ip_region,omitempty"`
	IPCity    string `bson:"ip_city,omitempty"`
	IPASN     string `bson:"ip_asn,omitempty"`

	// Token correlation
	TokenID      string `bson:"token_id,unique"`                // Corresponds to JTI of the JWT
	RefreshToken string `bson:"refresh_token,omitempty,unique"` // If using refresh tokens

	// Lifecycle
	CreatedAt   time.Time `bson:"created_at"`
	LastSeenAt  time.Time `bson:"last_seen_at,omitempty"`
	LastSeenIP  string    `bson:"last_seen_ip,omitempty"`
	ExpiresAt   time.Time `bson:"expires_at"`
	AbsoluteEnd time.Time `bson:"absolute_end,omitempty"`

	// Revocation
	IsRevoked    bool       `bson:"is_revoked,omitempty"`
	RevokedAt    *time.Time `bson:"revoked_at,omitempty"`
	RevokedBy    string     `bson:"revoked_by,omitempty"`
	RevokeReason string     `bson:"revoke_reason,omitempty"`
	RevokedFrom  string     `bson:"revoked_from,omitempty"`

	// Risk
	RiskFlags   []string `bson:"risk_flags,omitempty"`
	Trusted     bool     `bson:"trusted,omitempty"`
	BindKeyHash string   `bson:"bind_key_hash,omitempty"`

	// Back-compat
	LastUsedAt time.Time `bson:"last_used_at,omitempty"`
}

// SessionEvent is an append-only lifecycle log entry for a session.
type SessionEvent struct {
	ID        string         `bson:"_id,omitempty"`
	SessionID string         `bson:"session_id"`
	UserID    string         `bson:"user_id"`
	ClientID  string         `bson:"client_id,omitempty"`
	Type      string         `bson:"type"` // created|refreshed|rotated|reuse_detected|revoked|expired|risk_flagged|step_up
	IPAddress string         `bson:"ip_address,omitempty"`
	Geo       string         `bson:"geo,omitempty"`
	UserAgent string         `bson:"user_agent,omitempty"`
	At        time.Time      `bson:"at"`
	Actor     string         `bson:"actor,omitempty"`
	Reason    string         `bson:"reason,omitempty"`
	Metadata  map[string]any `bson:"metadata,omitempty"`
}

// LoginFlowState holds the parameters and state for an OIDC authorization flow
// that requires user authentication via the separate UI.
type LoginFlowState struct {
	FlowID                string            `bson:"_id,omitempty"`                   // Unique ID for this flow
	ClientID              string            `bson:"client_id"`                       //
	RedirectURI           string            `bson:"redirect_uri"`                    //
	Scope                 string            `bson:"scope"`                           //
	State                 string            `bson:"state"`                           // Client's state parameter
	Nonce                 string            `bson:"nonce,omitempty"`                 // Optional nonce from client
	Prompt                string            `bson:"prompt,omitempty"`                // Optional prompt parameter (login, none, consent)
	CodeChallenge         string            `bson:"code_challenge"`                  //
	CodeChallengeMethod   string            `bson:"code_challenge_method"`           //
	UserID                string            `bson:"user_id"`                         // Populated after successful user authentication
	UserAuthenticatedAt   time.Time         `bson:"user_authenticated_at,omitempty"` // Time of user authentication for this flow
	MFAEnrollmentVerified bool              `bson:"mfa_enrollment_verified"`         // Set after a successful TOTP enrollment in this flow; gates the enrollment completion
	ExpiresAt             time.Time         `bson:"expires_at"`                      // When this flow state should be considered invalid
	OriginalOIDCParams    map[string]string `bson:"original_oidc_params"`            // Store other original parameters if needed

	// Pending names the step that must still complete before this flow may be
	// turned into an authorization code: FlowPendingMFA while the second factor
	// is outstanding, or FlowPendingActionPrefix+<action> while a required action
	// (e.g. UPDATE_PASSWORD) is outstanding. Empty means fully authenticated.
	// UserID alone does NOT imply a finished login.
	Pending string `bson:"pending,omitempty"`
}

const (
	// FlowPendingMFA marks a flow whose password step passed but whose MFA step has not.
	FlowPendingMFA = "mfa"
	// FlowPendingActionPrefix prefixes the alias of an outstanding required action.
	FlowPendingActionPrefix = "action:"
)

// Authenticated reports whether the flow has an authenticated user and no outstanding step.
func (f *LoginFlowState) Authenticated() bool {
	return f != nil && f.UserID != "" && f.Pending == ""
}

// PendingAction returns the outstanding required action alias, or "".
func (f *LoginFlowState) PendingAction() string {
	if f != nil && len(f.Pending) > len(FlowPendingActionPrefix) && f.Pending[:len(FlowPendingActionPrefix)] == FlowPendingActionPrefix {
		return f.Pending[len(FlowPendingActionPrefix):]
	}
	return ""
}

// UserSession represents an active user session within the OIDC provider itself.
// This indicates that the user has logged into the provider.
type UserSession struct {
	SessionID       string    `bson:"_id,omitempty"`        // Secure random string, stored in the user's cookie
	UserID          string    `bson:"user_id"`              // ID of the authenticated user
	AuthenticatedAt time.Time `bson:"authenticated_at"`     // When this session was initiated
	ExpiresAt       time.Time `bson:"expires_at"`           // When this session expires
	UserAgent       string    `bson:"user_agent,omitempty"` // Optional: User-Agent of the client
	IPAddress       string    `bson:"ip_address,omitempty"` // Optional: IP address of the client
}
