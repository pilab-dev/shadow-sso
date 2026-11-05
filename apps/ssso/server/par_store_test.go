package server

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pilab-dev/shadow-sso/apps/ssso/config"
	"github.com/pilab-dev/shadow-sso/cache/parstore"
)

func TestNewPARStore(t *testing.T) {
	ctx := context.Background()

	store, err := newPARStore(ctx, config.Config{PARStoreBackend: "memory"}, nil)
	require.NoError(t, err)
	assert.Nil(t, store, "memory selects the default in-process store")

	store, err = newPARStore(ctx, config.Config{PARStoreBackend: "valkey", ValkeyURL: "redis://localhost:6379/0"}, nil)
	require.NoError(t, err)
	assert.IsType(t, &parstore.Redis{}, store)

	_, err = newPARStore(ctx, config.Config{PARStoreBackend: "valkey"}, nil)
	assert.Error(t, err, "valkey needs a URL")

	_, err = newPARStore(ctx, config.Config{PARStoreBackend: "mongodb"}, nil)
	assert.Error(t, err, "mongodb needs the mongo repository provider")

	_, err = newPARStore(ctx, config.Config{PARStoreBackend: "bogus"}, nil)
	assert.Error(t, err)
}
