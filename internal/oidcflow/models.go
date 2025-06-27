//go:generate go run go.uber.org/mock/mockgen@latest -source=$GOFILE -destination=mocks/mock_$GOFILE -package=mock_$GOPACKAGE
package oidcflow

import "time"

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
