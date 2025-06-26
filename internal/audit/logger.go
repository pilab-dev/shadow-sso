package audit

import (
	"encoding/json"
	"os"
	"time"

	"github.com/rs/zerolog/log"
)

// Event represents an audit log event.
type Event struct {
	Timestamp time.Time `json:"timestamp"`
	Service   string    `json:"service"`
	Action    string    `json:"action"`
	User      string    `json:"user,omitempty"`    // User ID or username
	Target    string    `json:"target,omitempty"`  // Target resource ID or name
	Details   string    `json:"details,omitempty"` // Additional details
	Success   bool      `json:"success"`
	Error     string    `json:"error,omitempty"` // Error message if the action failed
}

var auditLogger = log.Output(os.Stdout).With().Logger()

// Log records an audit event.
func Log(service, action, user, target, details string, success bool, err error) {
	event := Event{
		Timestamp: time.Now().UTC(),
		Service:   service,
		Action:    action,
		User:      user,
		Target:    target,
		Details:   details,
		Success:   success,
	}
	if err != nil {
		event.Error = err.Error()
	}

	entry, marshalErr := json.Marshal(event)
	if marshalErr != nil {
		// Fallback to unstructured logging if JSON marshaling fails
		log.Error().Err(marshalErr).Msg("Failed to marshal audit event to JSON")
		auditLogger.Error().
			Str("service", service).
			Str("action", action).
			Str("user", user).
			Str("target", target).
			Str("details", details).
			Bool("success", success).
			Err(err).
			Msg("Audit Log (fallback)")
		return
	}
	// Using zerolog's Ctx method with nil context to write raw JSON
	// This assumes that the global zerolog output is configured for JSON or console as desired.
	// If a separate audit log destination is needed (e.g., a different file),
	// a new zerolog.Logger instance should be created and configured for that.
	auditLogger.Log().RawJSON("audit_event", entry).Msg("")

}
