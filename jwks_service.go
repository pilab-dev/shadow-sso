package ssso

import (
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

func NewJWKSService(keyRotation time.Duration) (*JWKSService, error) {
	service := &JWKSService{
		keys:        make(map[string]*rsa.PrivateKey),
		keyRotation: keyRotation,
	}

	// Kezdeti kulcs generálása
	if err := service.rotateKeys(); err != nil {
		return nil, err
	}

	// Kulcs rotáció időzítő indítása
	go service.startKeyRotation()

	return service, nil
}

func (s *JWKSService) GetJWKS() JSONWebKeySet {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var keys []JSONWebKey
	for kid, privateKey := range s.keys {
		publicKey := privateKey.Public().(*rsa.PublicKey)

		// RSA kulcs komponensek kódolása
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

func (s *JWKSService) rotateKeys() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Új RSA kulcspár generálása
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("failed to generate RSA key: %w", err)
	}

	// Új kulcs ID generálása
	newKeyID := uuid.New().String()

	// Régi kulcs megtartása egy ideig az érvényes tokenek miatt
	if s.currentKeyID != "" {
		// Csak az utolsó kulcsot tartjuk meg
		delete(s.keys, s.currentKeyID)
	}

	s.keys[newKeyID] = privateKey
	s.currentKeyID = newKeyID

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
