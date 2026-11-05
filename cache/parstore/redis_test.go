package parstore_test

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pilab-dev/shadow-sso/cache/parstore"
	"github.com/pilab-dev/shadow-sso/domain"
)

func TestRedis_SingleUseBoundAndExpiring(t *testing.T) {
	mr := miniredis.RunT(t)
	store := parstore.NewRedis(redis.NewClient(&redis.Options{Addr: mr.Addr()}), "test")
	ctx := context.Background()

	require.NoError(t, store.Put(ctx, "u1", "c1", map[string]string{"scope": "openid"}, time.Minute))
	got, err := store.Consume(ctx, "u1", "c1")
	require.NoError(t, err)
	assert.Equal(t, "openid", got["scope"])
	_, err = store.Consume(ctx, "u1", "c1")
	assert.ErrorIs(t, err, domain.ErrPARNotFound, "request_uri is single use")

	require.NoError(t, store.Put(ctx, "u2", "c1", nil, time.Minute))
	_, err = store.Consume(ctx, "u2", "other")
	assert.ErrorIs(t, err, domain.ErrPARNotFound, "request_uri is bound to its client")

	require.NoError(t, store.Put(ctx, "u3", "c1", nil, time.Second))
	mr.FastForward(2 * time.Second)
	_, err = store.Consume(ctx, "u3", "c1")
	assert.ErrorIs(t, err, domain.ErrPARNotFound, "expired request_uri")
}
