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

type JWKSService struct {
	mu            sync.RWMutex
	keys          map[string]*rsa.PrivateKey
	currentKeyID  string
	previousKeyID string
	keyRotation   time.Duration
	gracePeriod   time.Duration
	keyCreatedAt  map[string]time.Time
	onRotation    func(keyID string, privateKey *rsa.PrivateKey)
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

func NewJWKSService(keyRotation time.Duration) (*JWKSService, error) {
	return NewJWKSServiceWithGrace(keyRotation, keyRotation)
}

func NewJWKSServiceWithGrace(keyRotation, gracePeriod time.Duration, onRotation ...func(keyID string, privateKey *rsa.PrivateKey)) (*JWKSService, error) {
	service := &JWKSService{
		keys:         make(map[string]*rsa.PrivateKey),
		keyRotation:  keyRotation,
		gracePeriod:  gracePeriod,
		keyCreatedAt: make(map[string]time.Time),
	}

	if len(onRotation) > 0 {
		service.onRotation = onRotation[0]
	}

	if err := service.rotateKeys(); err != nil {
		return nil, err
	}

	go service.startKeyRotation()

	return service, nil
}

func (s *JWKSService) GetPublicJWKS(ctx context.Context) (*JSONWebKeySet, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if len(s.keys) == 0 {
		return nil, fmt.Errorf("no keys available in JWKS service")
	}

	var keys []JSONWebKey
	for kid, privateKey := range s.keys {
		publicKey := privateKey.Public().(*rsa.PublicKey)

		n := base64.RawURLEncoding.EncodeToString(publicKey.N.Bytes())
		e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(publicKey.E)).Bytes())

		keys = append(keys, JSONWebKey{
			Kid: kid,
			Kty: "RSA",
			Alg: "RS256",
			Use: "sig",
			N:   n,
			E:   e,
		})
	}

	return &JSONWebKeySet{Keys: keys}, nil
}

func (s *JWKSService) GetJWKS() JSONWebKeySet {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var keys []JSONWebKey
	for kid, privateKey := range s.keys {
		publicKey := privateKey.Public().(*rsa.PublicKey)

		n := base64.RawURLEncoding.EncodeToString(publicKey.N.Bytes())
		e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(publicKey.E)).Bytes())

		keys = append(keys, JSONWebKey{
			Kid: kid,
			Kty: "RSA",
			Alg: "RS256",
			Use: "sig",
			N:   n,
			E:   e,
		})
	}

	return JSONWebKeySet{Keys: keys}
}

func (s *JWKSService) GetSigningKey() (string, *rsa.PrivateKey) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.currentKeyID, s.keys[s.currentKeyID]
}

func (s *JWKSService) OnRotation(callback func(keyID string, privateKey *rsa.PrivateKey)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.onRotation = callback
}

func (s *JWKSService) GetPublicKeyByID(kid string) *rsa.PublicKey {
	s.mu.RLock()
	defer s.mu.RUnlock()
	privKey, ok := s.keys[kid]
	if !ok {
		return nil
	}
	return privKey.Public().(*rsa.PublicKey)
}

func (s *JWKSService) rotateKeys() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("failed to generate RSA key: %w", err)
	}

	newKeyID := uuid.NewString()

	if s.currentKeyID != "" {
		s.previousKeyID = s.currentKeyID
	}

	s.keys[newKeyID] = privateKey
	s.keyCreatedAt[newKeyID] = time.Now()

	if s.onRotation != nil {
		s.onRotation(newKeyID, privateKey)
	}

	s.currentKeyID = newKeyID

	now := time.Now()
	for kid, createdAt := range s.keyCreatedAt {
		if kid != s.currentKeyID && kid != s.previousKeyID {
			delete(s.keys, kid)
			delete(s.keyCreatedAt, kid)
			continue
		}
		if kid == s.previousKeyID && now.Sub(createdAt) > s.gracePeriod {
			delete(s.keys, kid)
			delete(s.keyCreatedAt, kid)
			s.previousKeyID = ""
		}
	}

	return nil
}

func (s *JWKSService) startKeyRotation() {
	ticker := time.NewTicker(s.keyRotation)
	defer ticker.Stop()

	for range ticker.C {
		if err := s.rotateKeys(); err != nil {
			log.Error().Err(err).Msg("failed to rotate JWKS keys")
		}
	}
}
