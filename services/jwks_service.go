package services

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec // x5t is SHA-1 by definition
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"math/big"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
)

type defaultJWKSService struct {
	mu           sync.RWMutex
	keys         map[string]*rsa.PrivateKey
	currentKeyID string
	keyRotation  time.Duration
}

type JSONWebKey struct {
	Kid string `json:"kid"`
	Kty string `json:"kty"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	N   string `json:"n,omitempty"`
	E   string `json:"e,omitempty"`

	// EC and OKP keys (RFC 7518 §6.2, RFC 8037).
	Crv string `json:"crv,omitempty"`
	X   string `json:"x,omitempty"`
	Y   string `json:"y,omitempty"`

	// Certificate chain and thumbprints (RFC 7517 §4.6-4.9), as Keycloak publishes.
	X5c     []string `json:"x5c,omitempty"`
	X5t     string   `json:"x5t,omitempty"`
	X5tS256 string   `json:"x5t#S256,omitempty"`
}

type JSONWebKeySet struct {
	Keys []JSONWebKey `json:"keys"`
}

// newDefaultJWKSService creates a new JWKS service with key rotation (internal constructor).
func newDefaultJWKSService(keyRotation time.Duration) (JWKSService, error) {
	service := &defaultJWKSService{
		keys:        make(map[string]*rsa.PrivateKey),
		keyRotation: keyRotation,
	}

	if err := service.rotateKeys(); err != nil {
		return nil, err
	}

	go service.startKeyRotation()

	return service, nil
}

// NewJWKSService creates a new JWKS service with key rotation (public constructor for backward compatibility).
func NewJWKSService(keyRotation time.Duration) (*defaultJWKSService, error) {
	service := &defaultJWKSService{
		keys:        make(map[string]*rsa.PrivateKey),
		keyRotation: keyRotation,
	}

	if err := service.rotateKeys(); err != nil {
		return nil, err
	}

	go service.startKeyRotation()

	return service, nil
}

// NewJWKSServiceWithKey creates a JWKS service backed by an existing RSA key pair.
// This ensures the JWKS endpoint serves the same public key that corresponds to the
// private key used for signing tokens, making signature verification work.
// No automatic key rotation is performed — the provided key is the only key served.
func NewJWKSServiceWithKey(privKey *rsa.PrivateKey, kid string) *defaultJWKSService {
	service := &defaultJWKSService{
		keys:         make(map[string]*rsa.PrivateKey),
		keyRotation:  0, // no rotation for externally-provided keys
		currentKeyID: kid,
	}
	service.keys[kid] = privKey
	return service
}

// jsonWebKeyFromPublicKey converts an RSA public key into a JWKS entry.
func jsonWebKeyFromPublicKey(kid string, publicKey *rsa.PublicKey) JSONWebKey {
	// RSA kulcs komponensek kódolása
	n := base64.RawURLEncoding.EncodeToString(publicKey.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(publicKey.E)).Bytes())

	return JSONWebKey{
		Kid: kid,
		Kty: "RSA",
		Alg: "RS256",
		Use: "sig",
		N:   n,
		E:   e,
	}
}

// GetPublicJWKS retrieves the public JSON Web Key Set.
func (s *defaultJWKSService) GetPublicJWKS(ctx context.Context) (*JSONWebKeySet, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if len(s.keys) == 0 {
		return nil, fmt.Errorf("no keys available in JWKS service")
	}

	keys := make([]JSONWebKey, 0, len(s.keys))
	for kid, privateKey := range s.keys {
		publicKey := privateKey.Public().(*rsa.PublicKey)
		keys = append(keys, jsonWebKeyFromPublicKey(kid, publicKey))
	}

	return &JSONWebKeySet{Keys: keys}, nil
}

// GetJWKS retrieves the JSON Web Key Set.
func (s *defaultJWKSService) GetJWKS() JSONWebKeySet {
	s.mu.RLock()
	defer s.mu.RUnlock()

	keys := make([]JSONWebKey, 0, len(s.keys))
	for kid, privateKey := range s.keys {
		publicKey := privateKey.Public().(*rsa.PublicKey)
		keys = append(keys, jsonWebKeyFromPublicKey(kid, publicKey))
	}

	return JSONWebKeySet{Keys: keys}
}

// signerJWKSService serves the JSON Web Key Set from the TokenSigner's key
// registry, so the JWKS endpoint always reflects the exact keys used for
// signing: the realm-default key, per-client keys, and retiring keys kept
// for verification during rotation.
type signerJWKSService struct {
	signer *TokenSigner
}

// NewJWKSServiceFromSigner creates a JWKS service backed by the signer's
// key registry. The served key set is derived live from the registry, so
// rotations picked up by the signer are reflected automatically.
func NewJWKSServiceFromSigner(signer *TokenSigner) JWKSService {
	return &signerJWKSService{signer: signer}
}

// GetPublicJWKS retrieves the public JSON Web Key Set from the signer's
// active and retiring keys.
func (s *signerJWKSService) GetPublicJWKS(ctx context.Context) (*JSONWebKeySet, error) {
	if len(s.signer.PublicKeyInfos()) == 0 {
		return nil, fmt.Errorf("no keys available in JWKS service")
	}

	return &JSONWebKeySet{Keys: s.keys()}, nil
}

func (s *signerJWKSService) keys() []JSONWebKey {
	infos := s.signer.PublicKeyInfos()
	keys := make([]JSONWebKey, 0, len(infos))
	for _, info := range infos {
		jwk := jsonWebKeyFromInfo(info)
		if len(info.CertDER) > 0 {
			sha1Sum := sha1.Sum(info.CertDER) //nolint:gosec // x5t is defined as SHA-1 by RFC 7515
			sha256Sum := sha256.Sum256(info.CertDER)
			jwk.X5c = []string{base64.StdEncoding.EncodeToString(info.CertDER)}
			jwk.X5t = base64.RawURLEncoding.EncodeToString(sha1Sum[:])
			jwk.X5tS256 = base64.RawURLEncoding.EncodeToString(sha256Sum[:])
		}
		keys = append(keys, jwk)
	}
	return keys
}

// GetJWKS retrieves the JSON Web Key Set.
func (s *signerJWKSService) GetJWKS() JSONWebKeySet {
	return JSONWebKeySet{Keys: s.keys()}
}

// GetSigningKey retrieves the current realm-default signing key.
func (s *signerJWKSService) GetSigningKey() (string, interface{}) {
	return s.signer.RealmDefaultKeyID(), s.signer.GetRSAPrivateKey()
}

// GetSigningKey retrieves the current signing key.
func (s *defaultJWKSService) GetSigningKey() (string, interface{}) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.currentKeyID, s.keys[s.currentKeyID]
}

func (s *defaultJWKSService) rotateKeys() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Új RSA kulcspár generálása
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("failed to generate RSA key: %w", err)
	}

	// Új kulcs ID generálása
	newKeyID := uuid.NewString()

	// Régi kulcs megtartása egy ideig az érvényes tokenek miatt
	if s.currentKeyID != "" {
		// Csak az utolsó kulcsot tartjuk meg
		delete(s.keys, s.currentKeyID)
	}

	s.keys[newKeyID] = privateKey
	s.currentKeyID = newKeyID

	return nil
}

func (s *defaultJWKSService) startKeyRotation() {
	ticker := time.NewTicker(s.keyRotation)
	defer ticker.Stop()

	for range ticker.C {
		if err := s.rotateKeys(); err != nil {
			log.Error().Err(err).Msg("failed to rotate JWKS keys")
		}
	}
}

// jsonWebKeyFromInfo builds the JWKS entry for RSA, EC and Ed25519 keys.
func jsonWebKeyFromInfo(info PublicKeyInfo) JSONWebKey {
	switch pub := info.Public.(type) {
	case *ecdsa.PublicKey:
		size := (pub.Curve.Params().BitSize + 7) / 8
		return JSONWebKey{
			Kid: info.KeyID, Kty: "EC", Alg: info.Alg, Use: "sig",
			Crv: pub.Curve.Params().Name,
			X:   base64.RawURLEncoding.EncodeToString(pub.X.FillBytes(make([]byte, size))),
			Y:   base64.RawURLEncoding.EncodeToString(pub.Y.FillBytes(make([]byte, size))),
		}
	case ed25519.PublicKey:
		return JSONWebKey{
			Kid: info.KeyID, Kty: "OKP", Alg: "EdDSA", Use: "sig", Crv: "Ed25519",
			X: base64.RawURLEncoding.EncodeToString(pub),
		}
	}
	jwk := jsonWebKeyFromPublicKey(info.KeyID, info.Key)
	if info.Alg != "" {
		jwk.Alg = info.Alg
	}
	return jwk
}
