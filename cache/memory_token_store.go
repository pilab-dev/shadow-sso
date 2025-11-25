package cache

import (
	"context"
	"sync"
	"time"
)

// MemoryTokenStore implements TokenStore using in-memory storage
type MemoryTokenStore struct {
	tokens map[string]*TokenEntry
	mu     sync.RWMutex
}

// NewMemoryTokenStore creates a new in-memory TokenStore
func NewMemoryTokenStore(ttl time.Duration) TokenStore {
	store := &MemoryTokenStore{
		tokens: make(map[string]*TokenEntry),
	}

	// Start cleanup goroutine
	go func() {
		ticker := time.NewTicker(ttl / 4) // Cleanup every 1/4 of TTL
		defer ticker.Stop()
		for range ticker.C {
			store.DeleteExpired(context.Background())
		}
	}()

	return store
}

// Set stores a token entry
func (m *MemoryTokenStore) Set(ctx context.Context, entry *TokenEntry) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	tokenHash := HashToken(entry.TokenValue)
	m.tokens[tokenHash] = entry
	return nil
}

// Get retrieves a token entry
func (m *MemoryTokenStore) Get(ctx context.Context, token string) (*TokenEntry, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	tokenHash := HashToken(token)
	entry, exists := m.tokens[tokenHash]
	if !exists {
		return nil, nil // Or error, but for simplicity
	}
	// Update LastUsedAt
	entry.LastUsedAt = time.Now()
	return entry, nil
}

// Delete removes a token
func (m *MemoryTokenStore) Delete(ctx context.Context, token string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	tokenHash := HashToken(token)
	delete(m.tokens, tokenHash)
	return nil
}

// DeleteExpired removes expired tokens
func (m *MemoryTokenStore) DeleteExpired(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	for hash, entry := range m.tokens {
		if entry.ExpiresAt.Before(now) {
			delete(m.tokens, hash)
		}
	}
	return nil
}

// Clear removes all tokens
func (m *MemoryTokenStore) Clear(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.tokens = make(map[string]*TokenEntry)
	return nil
}

// Count returns the number of tokens
func (m *MemoryTokenStore) Count(ctx context.Context) int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.tokens)
}