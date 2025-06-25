package oidcflow

import (
	"errors"
	"sync"
	"time"

	"github.com/google/uuid"
)

var (
	ErrFlowNotFound      = errors.New("login flow not found")
	ErrFlowExpired       = errors.New("login flow expired")
	ErrSessionNotFound   = errors.New("user session not found")
	ErrSessionExpired    = errors.New("user session expired")
	ErrSessionIDConflict = errors.New("session ID conflict")
)

// InMemoryFlowStore stores LoginFlowState in memory.
type InMemoryFlowStore struct {
	mu    sync.RWMutex
	flows map[string]LoginFlowState
}

// NewInMemoryFlowStore creates a new InMemoryFlowStore.
func NewInMemoryFlowStore() *InMemoryFlowStore {
	return &InMemoryFlowStore{
		flows: make(map[string]LoginFlowState),
	}
}

// StoreFlow adds a new login flow state to the store.
func (s *InMemoryFlowStore) StoreFlow(flowID string, state LoginFlowState) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.flows[flowID] = state
	return nil
}

// GetFlow retrieves a login flow state by its ID.
// It also checks for expiry.
func (s *InMemoryFlowStore) GetFlow(flowID string) (*LoginFlowState, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	state, ok := s.flows[flowID]
	if !ok {
		return nil, ErrFlowNotFound
	}
	if time.Now().After(state.ExpiresAt) {
		// Optionally delete expired flow here
		// go s.DeleteFlow(flowID) // if deletion is desired on access
		return &state, ErrFlowExpired
	}
	return &state, nil
}

// UpdateFlow updates an existing login flow state.
func (s *InMemoryFlowStore) UpdateFlow(flowID string, state *LoginFlowState) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.flows[flowID]
	if !ok {
		return ErrFlowNotFound
	}
	s.flows[flowID] = *state
	return nil
}

// DeleteFlow removes a login flow state from the store.
func (s *InMemoryFlowStore) DeleteFlow(flowID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.flows, flowID)
	return nil
}

// InMemoryUserSessionStore stores UserSession in memory.
type InMemoryUserSessionStore struct {
	mu       sync.RWMutex
	sessions map[string]UserSession // Keyed by SessionID
}

// NewInMemoryUserSessionStore creates a new InMemoryUserSessionStore.
func NewInMemoryUserSessionStore() *InMemoryUserSessionStore {
	return &InMemoryUserSessionStore{
		sessions: make(map[string]UserSession),
	}
}

// StoreUserSession adds a new user session to the store.
// It generates a SessionID if not provided.
func (s *InMemoryUserSessionStore) StoreUserSession(session *UserSession) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if session.SessionID == "" {
		session.SessionID = uuid.NewString()
	} else {
		if _, exists := s.sessions[session.SessionID]; exists {
			return ErrSessionIDConflict // Or handle regeneration if ID collision is a concern with provided IDs
		}
	}
	s.sessions[session.SessionID] = *session
	return nil
}

// GetUserSession retrieves a user session by its ID.
// It also checks for expiry.
func (s *InMemoryUserSessionStore) GetUserSession(sessionID string) (*UserSession, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	session, ok := s.sessions[sessionID]
	if !ok {
		return nil, ErrSessionNotFound
	}

	if time.Now().After(session.ExpiresAt) {
		// Optionally delete expired session here
		// go s.DeleteUserSession(sessionID) // if deletion is desired on access
		return &session, ErrSessionExpired
	}
	return &session, nil
}

// DeleteUserSession removes a user session from the store.
func (s *InMemoryUserSessionStore) DeleteUserSession(sessionID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, sessionID)
	return nil
}

// CleanupExpiredFlows iterates through flows and removes expired ones.
// This should be called periodically by a background goroutine.
func (s *InMemoryFlowStore) CleanupExpiredFlows() {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for id, flow := range s.flows {
		if now.After(flow.ExpiresAt) {
			delete(s.flows, id)
		}
	}
}

// CleanupExpiredSessions iterates through sessions and removes expired ones.
// This should be called periodically by a background goroutine.
func (s *InMemoryUserSessionStore) CleanupExpiredSessions() {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for id, session := range s.sessions {
		if now.After(session.ExpiresAt) {
			delete(s.sessions, id)
		}
	}
}
