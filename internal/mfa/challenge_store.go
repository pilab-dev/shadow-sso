package mfa

import (
	"context"
	"sync"
	"time"

	"github.com/pilab-dev/shadow-sso/domain"
)

// InMemoryChallengeStore is a process-local MFAChallengeStore. Suitable for
// single-replica deployments; swap for a Redis-backed store in multi-replica.
type InMemoryChallengeStore struct {
	mu      sync.Mutex
	records map[string]*domain.MFAChallengeRecord
}

func NewInMemoryChallengeStore() *InMemoryChallengeStore {
	s := &InMemoryChallengeStore{records: make(map[string]*domain.MFAChallengeRecord)}
	go s.cleanup()
	return s
}

func (s *InMemoryChallengeStore) Put(ctx context.Context, record *domain.MFAChallengeRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := *record
	s.records[record.Key] = &cp
	return nil
}

func (s *InMemoryChallengeStore) Get(ctx context.Context, key string) (*domain.MFAChallengeRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.records[key]
	if !ok || time.Now().After(r.ExpiresAt) {
		return nil, domain.ErrUserNotFound // reuse sentinel for "not found"
	}
	cp := *r
	return &cp, nil
}

func (s *InMemoryChallengeStore) Consume(ctx context.Context, key string) (*domain.MFAChallengeRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.records[key]
	if !ok || time.Now().After(r.ExpiresAt) || r.Used {
		return nil, domain.ErrUserNotFound
	}
	r.Used = true
	cp := *r
	return &cp, nil
}

func (s *InMemoryChallengeStore) Delete(ctx context.Context, key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.records, key)
	return nil
}

func (s *InMemoryChallengeStore) CleanupExpired(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for k, r := range s.records {
		if now.After(r.ExpiresAt) {
			delete(s.records, k)
		}
	}
	return nil
}

func (s *InMemoryChallengeStore) cleanup() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		_ = s.CleanupExpired(context.Background())
	}
}
