package domain

import "time"

// Session represents an active user session.
// This could be stored in Redis for quick access and MongoDB for longer-term audit if needed.
type Session struct {
	ID           string    `bson:"_id,omitempty"` // Session ID (could be the JWT JTI)
	UserID       string    `bson:"user_id"`
	ClientID     string    `bson:"client_id,omitempty"`
	TokenID      string    `bson:"token_id,unique"`                // Corresponds to JTI of the JWT
	RefreshToken string    `bson:"refresh_token,omitempty,unique"` // If using refresh tokens
	UserAgent    string    `bson:"user_agent,omitempty"`
	IPAddress    string    `bson:"ip_address,omitempty"`
	ExpiresAt    time.Time `bson:"expires_at"`
	CreatedAt    time.Time `bson:"created_at"`
	LastUsedAt   time.Time `bson:"last_used_at,omitempty"` // Added LastUsedAt
	IsRevoked    bool      `bson:"is_revoked,omitempty"`   // To mark session as logged out
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
