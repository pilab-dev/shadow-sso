package audit

import (
	"context"
	"sync"
	"time"

	"github.com/pilab-dev/shadow-sso/domain"
)

// Sink is the persistence destination for audit events. domain.AuditLogRepository
// satisfies it, keeping the internal/audit package decoupled from Mongo.
type Sink interface {
	Insert(ctx context.Context, event *domain.AuditLog) error
}

var (
	sinkMu sync.RWMutex
	sink   Sink
)

// SetSink installs (or clears, with nil) the async persistence destination.
// Wiring is a one-time server bootstrap step; the sink is never replaced at
// runtime once the server is serving traffic.
func SetSink(s Sink) {
	sinkMu.Lock()
	defer sinkMu.Unlock()
	sink = s
}

func getSink() Sink {
	sinkMu.RLock()
	defer sinkMu.RUnlock()
	return sink
}

// persistAsync hands the event to the sink on a background goroutine. It never
// blocks the caller and never returns an error: persistence failures are
// logged and dropped, so a downed database cannot slow down or break the auth
// path. No sink configured → no-op.
func persistAsync(event Event) {
	s := getSink()
	if s == nil {
		return
	}

	log := &domain.AuditLog{
		Timestamp: event.Timestamp,
		Service:   event.Service,
		Action:    event.Action,
		User:      event.User,
		Target:    event.Target,
		Details:   event.Details,
		Success:   event.Success,
		Error:     event.Error,
	}

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := s.Insert(ctx, log); err != nil {
			auditLogger.Error().Err(err).
				Str("service", event.Service).
				Str("action", event.Action).
				Msg("Failed to persist audit event")
		}
	}()
}
