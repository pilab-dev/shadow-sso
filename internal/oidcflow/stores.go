package oidcflow

import (
	"context"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/pilab-dev/shadow-sso/domain" // Added domain import
)

// InMemoryFlowStore stores domain.LoginFlowState in memory.
type InMemoryFlowStore struct {
	mu    sync.RWMutex
	flows map[string]domain.LoginFlowState // Changed to domain.LoginFlowState
}

// NewInMemoryFlowStore creates a new InMemoryFlowStore.
func NewInMemoryFlowStore() *InMemoryFlowStore {
	return &InMemoryFlowStore{
		flows: make(map[string]domain.LoginFlowState), // Changed to domain.LoginFlowState
	}
}

// StoreFlow adds a new login flow state to the store.
func (s *InMemoryFlowStore) StoreFlow(ctx context.Context, flowID string, state domain.LoginFlowState) error { // Changed to domain.LoginFlowState
	s.mu.Lock()
	defer s.mu.Unlock()
	s.flows[flowID] = state
	return nil
}

// GetFlow retrieves a login flow state by its ID.
// It also checks for expiry.
func (s *InMemoryFlowStore) GetFlow(ctx context.Context, flowID string) (*domain.LoginFlowState, error) { // Changed to domain.LoginFlowState
	s.mu.RLock()
	defer s.mu.RUnlock()
	state, ok := s.flows[flowID]
	if !ok {
		return nil, domain.ErrFlowNotFound
	}
	if time.Now().After(state.ExpiresAt) {
		// Optionally delete expired flow here
		// go s.DeleteFlow(flowID) // if deletion is desired on access
		return &state, domain.ErrFlowExpired
	}
	return &state, nil
}

// UpdateFlow updates an existing login flow state.
func (s *InMemoryFlowStore) UpdateFlow(ctx context.Context, flowID string, state *domain.LoginFlowState) error { // Changed to domain.LoginFlowState
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.flows[flowID]
	if !ok {
		return domain.ErrFlowNotFound
	}
	s.flows[flowID] = *state
	return nil
}

// DeleteFlow removes a login flow state from the store.
func (s *InMemoryFlowStore) DeleteFlow(ctx context.Context, flowID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.flows, flowID)
	return nil
}

// InMemoryUserSessionStore stores domain.UserSession in memory.
type InMemoryUserSessionStore struct {
	mu       sync.RWMutex
	sessions map[string]domain.UserSession // Changed to domain.UserSession
}

// NewInMemoryUserSessionStore creates a new InMemoryUserSessionStore.
func NewInMemoryUserSessionStore() *InMemoryUserSessionStore {
	return &InMemoryUserSessionStore{
		sessions: make(map[string]domain.UserSession), // Changed to domain.UserSession
	}
}

// StoreUserSession adds a new user session to the store.
// It generates a SessionID if not provided.
func (s *InMemoryUserSessionStore) StoreUserSession(ctx context.Context, session *domain.UserSession) error { // Changed to domain.UserSession
	s.mu.Lock()
	defer s.mu.Unlock()

	if session.SessionID == "" {
		session.SessionID = uuid.NewString()
	} else {
		if _, exists := s.sessions[session.SessionID]; exists {
			return domain.ErrSessionIDConflict // Or handle regeneration if ID collision is a concern with provided IDs
		}
	}
	s.sessions[session.SessionID] = *session
	return nil
}

// GetUserSession retrieves a user session by its ID.
// It also checks for expiry.
func (s *InMemoryUserSessionStore) GetUserSession(ctx context.Context, sessionID string) (*domain.UserSession, error) { // Changed to domain.UserSession
	s.mu.RLock()
	defer s.mu.RUnlock()

	session, ok := s.sessions[sessionID]
	if !ok {
		return nil, domain.ErrSessionNotFound
	}

	if time.Now().After(session.ExpiresAt) {
		// Optionally delete expired session here
		// go s.DeleteUserSession(sessionID) // if deletion is desired on access
		return &session, domain.ErrSessionExpired
	}
	return &session, nil
}

// DeleteUserSession removes a user session from the store.
func (s *InMemoryUserSessionStore) DeleteUserSession(ctx context.Context, sessionID string) error {
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
