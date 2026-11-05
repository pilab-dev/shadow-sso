package mongodb

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"github.com/pilab-dev/shadow-sso/domain"
	"github.com/pilab-dev/shadow-sso/port"
)

// MongoKeyStore adapts the RealmKeysRepository to the port.KeyStore interface,
// giving ShadowSSO a pluggable, DB-backed key/certificate store.
type MongoKeyStore struct {
	repo domain.RealmKeysRepository
}

// NewMongoKeyStore wraps an existing RealmKeysRepository.
func NewMongoKeyStore(repo domain.RealmKeysRepository) port.KeyStore {
	return &MongoKeyStore{repo: repo}
}

func (s *MongoKeyStore) toStored(k *domain.RealmKey) *port.StoredKey {
	if k == nil {
		return nil
	}
	return &port.StoredKey{
		ID:         k.ID,
		Algorithm:  port.KeyAlgorithm(k.Type),
		ClientID:   k.ClientID,
		PublicPEM:  []byte(k.PublicKey),
		PrivatePEM: []byte(k.PrivateKey),
		Status:     k.Status,
	}
}

func (s *MongoKeyStore) fromStored(k *port.StoredKey) *domain.RealmKey {
	if k == nil {
		return nil
	}
	return &domain.RealmKey{
		ID:         k.ID,
		Type:       string(k.Algorithm),
		ClientID:   k.ClientID,
		PublicKey:  string(k.PublicPEM),
		PrivateKey: string(k.PrivatePEM),
		Status:     k.Status,
	}
}

func (s *MongoKeyStore) Generate(ctx context.Context, spec port.KeySpec) (*port.StoredKey, error) {
	switch spec.Algorithm {
	case port.KeyAlgorithmRSA, "":
	default:
		return nil, fmt.Errorf("unsupported algorithm: %s", spec.Algorithm)
	}
	size := spec.Size
	if size == 0 {
		size = 2048
	}
	priv, err := rsa.GenerateKey(rand.Reader, size)
	if err != nil {
		return nil, err
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		return nil, err
	}
	pubBytes := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})
	privBytes := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	key := &domain.RealmKey{
		ID:         spec.ID,
		Type:       string(port.KeyAlgorithmRSA),
		ClientID:   spec.ClientID,
		PublicKey:  string(pubBytes),
		PrivateKey: string(privBytes),
		Status:     domain.RealmKeyStatusActive,
	}
	if key.ID == "" {
		key.ID = NewID()
	}
	if err := s.repo.SaveRealmKey(ctx, key); err != nil {
		return nil, err
	}
	return s.toStored(key), nil
}

func (s *MongoKeyStore) Get(ctx context.Context, id string) (*port.StoredKey, error) {
	keys, err := s.repo.ListAllKeys(ctx)
	if err != nil {
		return nil, err
	}
	for _, k := range keys {
		if k.ID == id {
			return s.toStored(k), nil
		}
	}
	return nil, fmt.Errorf("key not found: %s", id)
}

func (s *MongoKeyStore) List(ctx context.Context, clientID string) ([]*port.StoredKey, error) {
	var keys []*domain.RealmKey
	var err error
	if clientID == "" {
		keys, err = s.repo.ListRealmKeys(ctx)
	} else {
		keys, err = s.repo.ListClientKeys(ctx, clientID)
	}
	if err != nil {
		return nil, err
	}
	out := make([]*port.StoredKey, 0, len(keys))
	for _, k := range keys {
		out = append(out, s.toStored(k))
	}
	return out, nil
}

func (s *MongoKeyStore) Rotate(ctx context.Context, id string) error {
	return s.repo.UpdateRealmKeyStatus(ctx, id, domain.RealmKeyStatusActive)
}

func (s *MongoKeyStore) Revoke(ctx context.Context, id string) error {
	return s.repo.UpdateRealmKeyStatus(ctx, id, domain.RealmKeyStatusRevoked)
}

func (s *MongoKeyStore) Import(ctx context.Context, key *port.StoredKey) error {
	return s.repo.SaveRealmKey(ctx, s.fromStored(key))
}
