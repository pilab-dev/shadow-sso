package mongodb

import (
	"context"
	"testing"

	"github.com/pilab-dev/shadow-sso/domain"
	"github.com/pilab-dev/shadow-sso/port"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeRealmKeysRepo struct {
	keys map[string]*domain.RealmKey
}

func newFakeRealmKeysRepo() *fakeRealmKeysRepo {
	return &fakeRealmKeysRepo{keys: make(map[string]*domain.RealmKey)}
}

func (f *fakeRealmKeysRepo) ListRealmKeys(ctx context.Context) ([]*domain.RealmKey, error) {
	var out []*domain.RealmKey
	for _, k := range f.keys {
		if k.ClientID == "" {
			out = append(out, k)
		}
	}
	return out, nil
}

func (f *fakeRealmKeysRepo) ListClientKeys(ctx context.Context, clientID string) ([]*domain.RealmKey, error) {
	var out []*domain.RealmKey
	for _, k := range f.keys {
		if k.ClientID == clientID {
			out = append(out, k)
		}
	}
	return out, nil
}

func (f *fakeRealmKeysRepo) ListAllKeys(ctx context.Context) ([]*domain.RealmKey, error) {
	out := make([]*domain.RealmKey, 0, len(f.keys))
	for _, k := range f.keys {
		out = append(out, k)
	}
	return out, nil
}

func (f *fakeRealmKeysRepo) SaveRealmKey(ctx context.Context, key *domain.RealmKey) error {
	f.keys[key.ID] = key
	return nil
}

func (f *fakeRealmKeysRepo) UpdateRealmKeyStatus(ctx context.Context, keyID string, status domain.RealmKeyStatus) error {
	if k, ok := f.keys[keyID]; ok {
		k.Status = status
	}
	return nil
}

func (f *fakeRealmKeysRepo) UpdateRealmKeys(ctx context.Context, keys []*domain.RealmKey) error {
	for _, k := range keys {
		f.keys[k.ID] = k
	}
	return nil
}

func TestMongoKeyStore_GenerateAlgorithms(t *testing.T) {
	store := NewMongoKeyStore(newFakeRealmKeysRepo())
	for _, algo := range []port.KeyAlgorithm{port.KeyAlgorithmRSA, port.KeyAlgorithmEC, port.KeyAlgorithmDSA} {
		key, err := store.Generate(context.Background(), port.KeySpec{Algorithm: algo})
		require.NoError(t, err, "algorithm %s", algo)
		assert.Equal(t, string(algo), string(key.Algorithm))
		assert.NotEmpty(t, key.PublicPEM)
		assert.NotEmpty(t, key.PrivatePEM)
		assert.Equal(t, domain.RealmKeyStatusActive, key.Status)
	}
}

func TestMongoKeyStore_RotateRevoke(t *testing.T) {
	repo := newFakeRealmKeysRepo()
	store := NewMongoKeyStore(repo)
	key, err := store.Generate(context.Background(), port.KeySpec{Algorithm: port.KeyAlgorithmRSA})
	require.NoError(t, err)

	require.NoError(t, store.Revoke(context.Background(), key.ID))
	got, err := store.Get(context.Background(), key.ID)
	require.NoError(t, err)
	assert.Equal(t, domain.RealmKeyStatusRevoked, got.Status)

	require.NoError(t, store.Rotate(context.Background(), key.ID))
	got, err = store.Get(context.Background(), key.ID)
	require.NoError(t, err)
	assert.Equal(t, domain.RealmKeyStatusActive, got.Status)
}
