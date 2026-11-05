package domain

import (
	"context"
	"time"
)

// MFAChallenge is the provider-agnostic challenge returned by an MFA provider.
type MFAChallenge struct {
	ID        string            `json:"id"`
	Provider  MfaMethodType     `json:"provider"`
	Challenge string            `json:"challenge,omitempty"`
	Options   []byte            `json:"options,omitempty"`
	ExpiresAt time.Time         `json:"expires_at"`
	Metadata  map[string]string `json:"metadata,omitempty"`
}

// MFAVerification is the provider-agnostic verification payload supplied by
// the client.
type MFAVerification struct {
	Response []byte            `json:"response"`
	Metadata map[string]string `json:"metadata,omitempty"`
}

// MFAChallengeRecord is the server-side record persisted between the Begin*
// and Complete*/Verify* calls.
type MFAChallengeRecord struct {
	Key         string        `json:"key"`
	UserID      string        `json:"user_id,omitempty"`
	Provider    MfaMethodType `json:"provider"`
	Challenge   string        `json:"challenge"`
	SessionData []byte        `json:"session_data,omitempty"`
	ExpiresAt   time.Time     `json:"expires_at"`
	Used        bool          `json:"used"`
}

var _ = context.Background
var _ = time.Now
