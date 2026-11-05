package parstore_test

import (
	"context"
	"testing"
	"time"

	"github.com/pilab-dev/shadow-sso/cache/parstore"
	"github.com/pilab-dev/shadow-sso/domain"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMemory_SingleUseBoundAndExpiring(t *testing.T) {
	m := parstore.NewMemory()
	defer m.Close()
	ctx := context.Background()

	require.NoError(t, m.Put(ctx, "u1", "c1", map[string]string{"scope": "openid"}, time.Minute))
	got, err := m.Consume(ctx, "u1", "c1")
	require.NoError(t, err)
	assert.Equal(t, "openid", got["scope"])
	_, err = m.Consume(ctx, "u1", "c1")
	assert.ErrorIs(t, err, domain.ErrPARNotFound)

	require.NoError(t, m.Put(ctx, "u2", "c1", nil, time.Minute))
	_, err = m.Consume(ctx, "u2", "other")
	assert.ErrorIs(t, err, domain.ErrPARNotFound)

	require.NoError(t, m.Put(ctx, "u3", "c1", nil, time.Millisecond))
	time.Sleep(20 * time.Millisecond)
	_, err = m.Consume(ctx, "u3", "c1")
	assert.ErrorIs(t, err, domain.ErrPARNotFound)
}
