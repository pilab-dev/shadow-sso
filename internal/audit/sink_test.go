package audit

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/pilab-dev/shadow-sso/domain"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// recordingSink captures inserted events for assertions; it satisfies Sink.
type recordingSink struct {
	mu     sync.Mutex
	events []*domain.AuditLog
	err    error
}

func (s *recordingSink) Insert(_ context.Context, event *domain.AuditLog) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return s.err
	}
	s.events = append(s.events, event)
	return nil
}

func (s *recordingSink) snapshot() []*domain.AuditLog {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*domain.AuditLog, len(s.events))
	copy(out, s.events)
	return out
}

func TestSetSinkAndGetSink(t *testing.T) {
	original := getSink()
	defer SetSink(original)

	s := &recordingSink{}
	SetSink(s)
	require.Same(t, s, getSink(), "getSink should return the installed sink")

	SetSink(nil)
	require.Nil(t, getSink(), "SetSink(nil) should clear the sink")
}

func TestPersistAsync_NoSinkIsNoop(t *testing.T) {
	original := getSink()
	defer SetSink(original)
	SetSink(nil)

	// Must neither panic nor block when no sink is configured.
	persistAsync(Event{Service: "user", Action: "create"})
}

func TestPersistAsync_PersistsEventToSink(t *testing.T) {
	original := getSink()
	defer SetSink(original)

	s := &recordingSink{}
	SetSink(s)

	event := Event{
		Timestamp: time.Now().UTC(),
		Service:   "user",
		Action:    "create",
		User:      "u1",
		Target:    "t1",
		Details:   "details",
		Success:   true,
	}
	persistAsync(event)

	// Wait for the background goroutine without racing on the sink state.
	deadline := time.Now().Add(2 * time.Second)
	var got []*domain.AuditLog
	for time.Now().Before(deadline) {
		if got = s.snapshot(); len(got) > 0 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	require.Len(t, got, 1, "event should reach the sink")

	ev := got[0]
	assert.Equal(t, event.Timestamp, ev.Timestamp)
	assert.Equal(t, event.Service, ev.Service)
	assert.Equal(t, event.Action, ev.Action)
	assert.Equal(t, event.User, ev.User)
	assert.Equal(t, event.Target, ev.Target)
	assert.Equal(t, event.Details, ev.Details)
	assert.True(t, ev.Success)
}

func TestPersistAsync_SinkErrorIsLoggedNotFatal(t *testing.T) {
	original := getSink()
	defer SetSink(original)

	s := &recordingSink{err: errors.New("db down")}
	SetSink(s)

	// A failing sink must never panic or block the caller; the error is
	// swallowed by the async goroutine (logged only).
	persistAsync(Event{Service: "user", Action: "create"})
	time.Sleep(50 * time.Millisecond)
}
