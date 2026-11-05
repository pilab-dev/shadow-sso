package parstore

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/pilab-dev/shadow-sso/domain"
	"github.com/redis/go-redis/v9"
)

type payload struct {
	ClientID string            `json:"client_id"`
	Params   map[string]string `json:"params"`
}

// Redis is a PARStore for Valkey or Redis (wire compatible). Consume uses the
// atomic GETDEL command, so a request_uri is single use across nodes.
type Redis struct {
	client redis.UniversalClient
	prefix string
}

func NewRedis(client redis.UniversalClient, prefix string) *Redis {
	if prefix == "" {
		prefix = "sso"
	}
	return &Redis{client: client, prefix: prefix}
}

func (r *Redis) key(uri string) string { return r.prefix + ":par:" + uri }

func (r *Redis) Put(ctx context.Context, uri, clientID string, params map[string]string, ttl time.Duration) error {
	b, err := json.Marshal(payload{ClientID: clientID, Params: params})
	if err != nil {
		return err
	}
	return r.client.Set(ctx, r.key(uri), b, ttl).Err()
}

func (r *Redis) Consume(ctx context.Context, uri, clientID string) (map[string]string, error) {
	b, err := r.client.GetDel(ctx, r.key(uri)).Bytes()
	if errors.Is(err, redis.Nil) {
		return nil, domain.ErrPARNotFound
	}
	if err != nil {
		return nil, err
	}
	var p payload
	if err := json.Unmarshal(b, &p); err != nil || p.ClientID != clientID {
		return nil, domain.ErrPARNotFound
	}
	return p.Params, nil
}
