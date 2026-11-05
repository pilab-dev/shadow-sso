// Package parstore provides domain.PARStore adapters: ttlcache (single node),
// Valkey/Redis (scaled deployments) and, in package mongodb, MongoDB with a TTL index.
package parstore

import (
	"context"
	"time"

	"github.com/jellydator/ttlcache/v3"
	"github.com/pilab-dev/shadow-sso/domain"
)

const maxMemoryEntries = 10000

type entry struct {
	clientID string
	params   map[string]string
}

// Memory is a process-local PARStore backed by ttlcache.
type Memory struct {
	cache *ttlcache.Cache[string, entry]
}

// NewMemory starts the background expiry loop; call Close to stop it.
func NewMemory() *Memory {
	c := ttlcache.New(ttlcache.WithCapacity[string, entry](maxMemoryEntries))
	go c.Start()
	return &Memory{cache: c}
}

func (m *Memory) Close() { m.cache.Stop() }

func (m *Memory) Put(_ context.Context, uri, clientID string, params map[string]string, ttl time.Duration) error {
	m.cache.Set(uri, entry{clientID: clientID, params: copyParams(params)}, ttl)
	return nil
}

func (m *Memory) Consume(_ context.Context, uri, clientID string) (map[string]string, error) {
	item, ok := m.cache.GetAndDelete(uri)
	if !ok || item.IsExpired() || item.Value().clientID != clientID {
		return nil, domain.ErrPARNotFound
	}
	return copyParams(item.Value().params), nil
}

func copyParams(in map[string]string) map[string]string {
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}
