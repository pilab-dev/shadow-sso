package mfa

import (
	"fmt"
	"sync"

	"github.com/pilab-dev/shadow-sso/domain"
	"github.com/pilab-dev/shadow-sso/port"
)

// DefaultMFARegistry is a thread-safe in-memory MFARegistry.
type DefaultMFARegistry struct {
	mu        sync.RWMutex
	providers map[domain.MfaMethodType]port.MFAProvider
}

func NewMFARegistry() *DefaultMFARegistry {
	return &DefaultMFARegistry{providers: make(map[domain.MfaMethodType]port.MFAProvider)}
}

func (r *DefaultMFARegistry) Register(provider port.MFAProvider) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.providers[provider.Type()]; exists {
		return fmt.Errorf("mfa provider %q already registered", provider.Type())
	}
	r.providers[provider.Type()] = provider
	return nil
}

func (r *DefaultMFARegistry) Get(methodType domain.MfaMethodType) (port.MFAProvider, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	p, ok := r.providers[methodType]
	return p, ok
}

func (r *DefaultMFARegistry) List() []port.MFAProvider {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]port.MFAProvider, 0, len(r.providers))
	for _, p := range r.providers {
		out = append(out, p)
	}
	return out
}
