package domain

import (
	"context"
	"errors"
	"time"
)

// ErrPARNotFound is returned when a request_uri is unknown, expired, already
// consumed or bound to a different client.
var ErrPARNotFound = errors.New("pushed authorization request not found")

// PARStore persists pushed authorization requests (RFC 9126).
// Implementations must make Consume atomic so a request_uri is single use.
type PARStore interface {
	// Put stores params for requestURI, bound to clientID, for ttl.
	Put(ctx context.Context, requestURI, clientID string, params map[string]string, ttl time.Duration) error
	// Consume atomically removes and returns the params. A request pushed by
	// a different client is treated as ErrPARNotFound (and is burned).
	Consume(ctx context.Context, requestURI, clientID string) (map[string]string, error)
}
