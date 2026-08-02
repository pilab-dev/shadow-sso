package services

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
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
	N   string `json:"n"`
	E   string `json:"e"`
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
		keys:        make(map[string]*rsa.PrivateKey),
		keyRotation: 0, // no rotation for externally-provided keys
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
	pubKeys := s.signer.PublicKeys()
	if len(pubKeys) == 0 {
		return nil, fmt.Errorf("no keys available in JWKS service")
	}

	keys := make([]JSONWebKey, 0, len(pubKeys))
	for kid, publicKey := range pubKeys {
		keys = append(keys, jsonWebKeyFromPublicKey(kid, publicKey))
	}
	return &JSONWebKeySet{Keys: keys}, nil
}

// GetJWKS retrieves the JSON Web Key Set.
func (s *signerJWKSService) GetJWKS() JSONWebKeySet {
	pubKeys := s.signer.PublicKeys()
	keys := make([]JSONWebKey, 0, len(pubKeys))
	for kid, publicKey := range pubKeys {
		keys = append(keys, jsonWebKeyFromPublicKey(kid, publicKey))
	}
	return JSONWebKeySet{Keys: keys}
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
