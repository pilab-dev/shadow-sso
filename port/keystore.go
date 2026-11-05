package port

import (
	"context"

	"github.com/pilab-dev/shadow-sso/domain"
)

// KeyAlgorithm identifies the kind of key a KeyStore manages.
type KeyAlgorithm string

const (
	KeyAlgorithmRSA KeyAlgorithm = "RSA"
	KeyAlgorithmDSA KeyAlgorithm = "DSA"
	KeyAlgorithmEC  KeyAlgorithm = "EC"
)

// KeySpec describes a key to be generated or imported.
type KeySpec struct {
	ID        string
	Algorithm KeyAlgorithm
	Size      int // bits, e.g. 2048 for RSA
	ClientID  string
}

// StoredKey is the material a KeyStore returns to callers. Private material is
// only present when the store is allowed to export it (file/DB stores); HSM
// stores return an opaque handle and never export private bytes.
type StoredKey struct {
	ID         string
	Algorithm  KeyAlgorithm
	ClientID   string
	PublicPEM  []byte
	PrivatePEM []byte // empty for non-exportable (HSM) stores
	Status     domain.RealmKeyStatus
}

// KeyStore is the port for external certificate/key storage. ShadowSSO's
// TokenSigner depends on this interface instead of a concrete repository, so
// operators can plug in an HSM, KMS, or filesystem-backed store without
// touching core code. Implementations must be safe for concurrent use.
type KeyStore interface {
	// Generate creates a new key according to spec and persists it.
	Generate(ctx context.Context, spec KeySpec) (*StoredKey, error)
	// Get returns the key with the given id, or an error if not found.
	Get(ctx context.Context, id string) (*StoredKey, error)
	// List returns all keys, optionally filtered by clientID ("" = realm default).
	List(ctx context.Context, clientID string) ([]*StoredKey, error)
	// Rotate marks the given key as the active one for its scope and retires
	// the previous active key (status -> retired).
	Rotate(ctx context.Context, id string) error
	// Revoke permanently disables a key.
	Revoke(ctx context.Context, id string) error
	// Import stores externally provided key material (PEM-encoded).
	Import(ctx context.Context, key *StoredKey) error
}