package services

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/rs/zerolog/log"

	"github.com/pilab-dev/shadow-sso/domain"
	pkgcrypto "github.com/pilab-dev/shadow-sso/pkg/crypto"
)

var ErrInvalidKeyID = errors.New("invalid key id")
var ErrInvalidRSAKey = errors.New("invalid RSA key")

type TokenSignerFunc func(claims jwt.Claims) (string, error)

// signingKey is a single key in the signer's kid-keyed registry.
// It holds both the signing function and the verification material.
type signingKey struct {
	id       string
	clientID string // "" = realm-default key
	status   domain.RealmKeyStatus
	priority int

	signer  TokenSignerFunc
	privKey *rsa.PrivateKey // nil for HS256 keys
	pubKey  *rsa.PublicKey  // nil for HS256 keys
	secret  []byte          // nil for RSA keys
}

// TokenSigner signs and verifies JWTs. It supports two modes:
//   - legacy: keys added via AddKeySigner/AddRSASigner (file/env based);
//   - registry-backed: keys loaded from the RealmKeysRepository via
//     LoadFromRepository, with per-client keys and rotation lifecycle.
//
// In registry-backed mode the DB is the source of truth; a background refresh
// keeps the in-memory registry in sync with other replicas.
type TokenSigner struct {
	mu           sync.RWMutex
	keys         map[string]*signingKey // kid -> key entry
	defaultKeyID string                 // realm-default active key ID (registry mode)

	// legacy single-key state (AddKeySigner/AddRSASigner)
	rsaPrivKey  *rsa.PrivateKey
	rsaPubKey   *rsa.PublicKey
	hs256Secret []byte

	// registry-backed state
	repo            domain.RealmKeysRepository
	encryptionKey   []byte
	refreshInterval time.Duration
	stopRefresh     chan struct{}
}

// NewTokenSigner creates a new Signer instance.
func NewTokenSigner() *TokenSigner {
	return &TokenSigner{
		keys: make(map[string]*signingKey),
	}
}

// AddKeySigner registers an HS256 signer under the "default" key ID (legacy mode).
func (s *TokenSigner) AddKeySigner(secretKey string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.hs256Secret = []byte(secretKey)
	secret := []byte(secretKey)
	s.keys["default"] = &signingKey{
		id:     "default",
		status: domain.RealmKeyStatusActive,
		signer: func(claims jwt.Claims) (string, error) {
			token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
			tokenString, err := token.SignedString(secret)
			if err != nil {
				return "", fmt.Errorf("failed to sign token: %w", err)
			}
			return tokenString, nil
		},
		secret: secret,
	}
}

// AddRSASigner loads an RSA private key from a PEM file and registers it under
// the "rsa-default" and "default" key IDs (legacy mode).
func (s *TokenSigner) AddRSASigner(keyPath string) error {
	keyData, err := os.ReadFile(keyPath)
	if err != nil {
		return fmt.Errorf("failed to read RSA key file: %w", err)
	}

	privKey, err := parseRSAPrivateKeyPEM(keyData)
	if err != nil {
		return err
	}

	if privKey.N.BitLen() < 2048 {
		return fmt.Errorf("RSA key too small: %d bits (minimum 2048)", privKey.N.BitLen())
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.rsaPrivKey = privKey
	s.rsaPubKey = &privKey.PublicKey

	entry := &signingKey{
		id:       "rsa-default",
		status:   domain.RealmKeyStatusActive,
		privKey:  privKey,
		pubKey:   &privKey.PublicKey,
		signer:   s.rsaSigner(privKey, "rsa-default"),
	}
	s.keys["rsa-default"] = entry
	s.keys["default"] = entry

	return nil
}

// rsaSigner returns a token signing function that signs with the given RSA key
// and sets the "kid" header.
func (s *TokenSigner) rsaSigner(privKey *rsa.PrivateKey, kid string) TokenSignerFunc {
	return func(claims jwt.Claims) (string, error) {
		token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		token.Header["kid"] = kid
		tokenString, err := token.SignedString(privKey)
		if err != nil {
			return "", fmt.Errorf("failed to sign token with RSA: %w", err)
		}
		return tokenString, nil
	}
}

// GetRSAPublicKey returns the RSA public key of the current default signer.
func (s *TokenSigner) GetRSAPublicKey() *rsa.PublicKey {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.rsaPubKey != nil {
		return s.rsaPubKey
	}
	if entry := s.keys[s.defaultKeyID]; entry != nil && entry.pubKey != nil {
		return entry.pubKey
	}
	return nil
}

// GetRSAPrivateKey returns the RSA private key of the current default signer.
func (s *TokenSigner) GetRSAPrivateKey() *rsa.PrivateKey {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.rsaPrivKey != nil {
		return s.rsaPrivKey
	}
	if entry := s.keys[s.defaultKeyID]; entry != nil && entry.privKey != nil {
		return entry.privKey
	}
	return nil
}

// ExportRSAPrivateKeyPEM returns the currently loaded default RSA private key
// encoded as PKCS#1 PEM, suitable for persisting to the key registry. Returns
// ErrInvalidRSAKey when no RSA key is loaded.
func (s *TokenSigner) ExportRSAPrivateKeyPEM() ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var privKey *rsa.PrivateKey
	switch {
	case s.rsaPrivKey != nil:
		privKey = s.rsaPrivKey
	case s.keys[s.defaultKeyID] != nil && s.keys[s.defaultKeyID].privKey != nil:
		privKey = s.keys[s.defaultKeyID].privKey
	default:
		return nil, ErrInvalidRSAKey
	}

	return pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privKey),
	}), nil
}

// HasRSASigner reports whether an RSA signing key is available.
func (s *TokenSigner) HasRSASigner() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.rsaPrivKey != nil {
		return true
	}
	if entry := s.keys[s.defaultKeyID]; entry != nil && entry.privKey != nil {
		return true
	}
	return false
}

// GetDefaultSigningMethod returns the signing method of the default key.
func (s *TokenSigner) GetDefaultSigningMethod() jwt.SigningMethod {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.rsaPrivKey != nil {
		return jwt.SigningMethodRS256
	}
	if entry := s.keys[s.defaultKeyID]; entry != nil {
		if entry.privKey != nil {
			return jwt.SigningMethodRS256
		}
		return jwt.SigningMethodHS256
	}
	return jwt.SigningMethodHS256
}

// Sign signs the given claims with the specified key ID.
// An empty keyID resolves to the realm-default active key (registry mode) or
// the first registered key (legacy mode).
func (s *TokenSigner) Sign(claims jwt.Claims, keyID string) (string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if keyID == "" {
		if s.defaultKeyID != "" {
			entry := s.keys[s.defaultKeyID]
			if entry == nil || entry.status != domain.RealmKeyStatusActive {
				return "", ErrInvalidKeyID
			}
			return entry.signer(claims)
		}
		// legacy mode: first registered key
		for _, entry := range s.keys {
			if entry != nil {
				return entry.signer(claims)
			}
		}
		return "", ErrInvalidKeyID
	}

	entry, ok := s.keys[keyID]
	if !ok {
		return "", ErrInvalidKeyID
	}
	if entry.status != domain.RealmKeyStatusActive {
		return "", fmt.Errorf("key %s is not active (status: %s)", keyID, entry.status)
	}
	return entry.signer(claims)
}

// ResolveSigningKeyID returns the key ID to sign tokens for a client:
// the client's dedicated active key if present, otherwise the realm-default
// active key.
func (s *TokenSigner) ResolveSigningKeyID(clientID string) (string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if clientID != "" {
		var best *signingKey
		for _, entry := range s.keys {
			if entry.clientID == clientID && entry.status == domain.RealmKeyStatusActive {
				if best == nil || entry.priority > best.priority {
					best = entry
				}
			}
		}
		if best != nil {
			return best.id, nil
		}
	}

	if s.defaultKeyID != "" {
		return s.defaultKeyID, nil
	}
	if _, ok := s.keys["default"]; ok {
		return "default", nil
	}
	return "", ErrInvalidKeyID
}

// SignForClient signs claims using the key resolved for the given client.
func (s *TokenSigner) SignForClient(claims jwt.Claims, clientID string) (string, error) {
	keyID, err := s.ResolveSigningKeyID(clientID)
	if err != nil {
		return "", err
	}
	return s.Sign(claims, keyID)
}

// lookupKey returns the verification entry for a kid, honoring the rotation
// lifecycle: active and retiring keys verify; revoked keys do not.
func (s *TokenSigner) lookupKey(kid string) *signingKey {
	if kid == "" {
		return nil
	}
	entry, ok := s.keys[kid]
	if !ok {
		return nil
	}
	if entry.status != domain.RealmKeyStatusActive && entry.status != domain.RealmKeyStatusRetiring {
		return nil
	}
	return entry
}

// VerifyToken verifies a JWT signature against the signer's configured keys
// (HS256 via the shared secret, RS256 via the RSA public keys) and validates
// standard exp/nbf claims. Verification material is selected by the token's
// "kid" header, falling back to the legacy single-key state.
func (s *TokenSigner) VerifyToken(tokenString string) (jwt.MapClaims, error) {
	claims := jwt.MapClaims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		kid, _ := token.Header["kid"].(string)

		s.mu.RLock()
		entry := s.lookupKey(kid)
		legacyHS := s.hs256Secret
		legacyRSA := s.rsaPubKey
		s.mu.RUnlock()

		switch token.Method.(type) {
		case *jwt.SigningMethodHMAC:
			if entry != nil && entry.secret != nil {
				return entry.secret, nil
			}
			if legacyHS != nil {
				return legacyHS, nil
			}
			return nil, errors.New("no HS256 secret configured for verification")
		case *jwt.SigningMethodRSA:
			if entry != nil && entry.pubKey != nil {
				return entry.pubKey, nil
			}
			if legacyRSA != nil {
				return legacyRSA, nil
			}
			return nil, errors.New("no RSA public key configured for verification")
		default:
			return nil, fmt.Errorf("unsupported signing method: %v", token.Header["alg"])
		}
	}, jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg(), jwt.SigningMethodRS256.Alg()}))

	if err != nil {
		return nil, fmt.Errorf("token verification failed: %w", err)
	}
	if !token.Valid {
		return nil, errors.New("token is invalid")
	}
	return claims, nil
}

// parseRSAPrivateKeyPEM parses an RSA private key from PKCS1 or PKCS8 PEM.
func parseRSAPrivateKeyPEM(keyData []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(keyData)
	if block == nil {
		return nil, ErrInvalidRSAKey
	}

	privKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		parsedKey, errParse := x509.ParsePKCS8PrivateKey(block.Bytes)
		if errParse != nil {
			return nil, fmt.Errorf("failed to parse RSA private key: %w (also tried PKCS8: %w)", err, errParse)
		}
		rsaKey, ok := parsedKey.(*rsa.PrivateKey)
		if !ok {
			return nil, ErrInvalidRSAKey
		}
		privKey = rsaKey
	}

	return privKey, nil
}

// LoadFromRepository loads all signing keys from the RealmKeysRepository into
// the in-memory registry, decrypting private keys at rest. The realm-default
// active key (highest priority) becomes the default signing key.
func (s *TokenSigner) LoadFromRepository(ctx context.Context, repo domain.RealmKeysRepository, encryptionKey []byte) error {
	allKeys, err := repo.ListAllKeys(ctx)
	if err != nil {
		return fmt.Errorf("failed to load signing keys from repository: %w", err)
	}

	registry := make(map[string]*signingKey, len(allKeys))
	var defaultKeyID string
	var defaultPriority int

	for _, rk := range allKeys {
		if rk.Status == domain.RealmKeyStatusRevoked {
			continue
		}
		entry, err := s.buildSigningKey(rk, encryptionKey)
		if err != nil {
			return fmt.Errorf("failed to build signing key %q: %w", rk.ID, err)
		}
		registry[rk.ID] = entry

		if rk.ClientID == "" && rk.Status == domain.RealmKeyStatusActive {
			if defaultKeyID == "" || rk.Priority > defaultPriority {
				defaultKeyID = rk.ID
				defaultPriority = rk.Priority
			}
		}
	}

	s.mu.Lock()
	s.keys = registry
	s.defaultKeyID = defaultKeyID
	s.repo = repo
	s.encryptionKey = encryptionKey
	s.mu.Unlock()

	if defaultKeyID == "" {
		log.Warn().Msg("no realm-default active signing key found in repository")
	}
	return nil
}

// buildSigningKey decrypts a RealmKey's private key and builds the in-memory
// signing entry for it. RSA keys sign with RS256, HS256 keys with HMAC.
func (s *TokenSigner) buildSigningKey(rk *domain.RealmKey, encryptionKey []byte) (*signingKey, error) {
	if rk.PrivateKey == "" {
		return nil, errors.New("signing key has no private key material")
	}

	plaintext, err := pkgcrypto.DecryptAESGCM(encryptionKey, rk.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt private key: %w", err)
	}

	switch rk.Type {
	case "HS256", "hs256":
		secret := []byte(plaintext)
		return &signingKey{
			id:       rk.ID,
			clientID: rk.ClientID,
			status:   rk.Status,
			priority: rk.Priority,
			signer: func(claims jwt.Claims) (string, error) {
				token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
				token.Header["kid"] = rk.ID
				tokenString, err := token.SignedString(secret)
				if err != nil {
					return "", fmt.Errorf("failed to sign token: %w", err)
				}
				return tokenString, nil
			},
			secret: secret,
		}, nil
	default: // "RSA" or empty
		privKey, err := parseRSAPrivateKeyPEM([]byte(plaintext))
		if err != nil {
			return nil, err
		}
		if privKey.N.BitLen() < 2048 {
			return nil, fmt.Errorf("RSA key too small: %d bits (minimum 2048)", privKey.N.BitLen())
		}
		return &signingKey{
			id:       rk.ID,
			clientID: rk.ClientID,
			status:   rk.Status,
			priority: rk.Priority,
			privKey:  privKey,
			pubKey:   &privKey.PublicKey,
			signer:   s.rsaSigner(privKey, rk.ID),
		}, nil
	}
}

// Refresh reloads the registry from the repository.
func (s *TokenSigner) Refresh(ctx context.Context) error {
	s.mu.RLock()
	repo := s.repo
	encryptionKey := s.encryptionKey
	s.mu.RUnlock()

	if repo == nil {
		return errors.New("signer is not registry-backed")
	}
	return s.LoadFromRepository(ctx, repo, encryptionKey)
}

// IsRegistryBacked reports whether the signer was loaded from the repository.
func (s *TokenSigner) IsRegistryBacked() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.repo != nil
}

// StartKeyRefresh starts a background loop that reloads the key registry from
// the repository every interval, picking up rotations from other replicas.
func (s *TokenSigner) StartKeyRefresh(ctx context.Context, interval time.Duration) {
	s.mu.Lock()
	if s.stopRefresh != nil {
		s.mu.Unlock()
		return
	}
	s.stopRefresh = make(chan struct{})
	s.refreshInterval = interval
	stop := s.stopRefresh
	s.mu.Unlock()

	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				if err := s.Refresh(ctx); err != nil {
					log.Error().Err(err).Msg("failed to refresh signing key registry")
				}
			case <-stop:
				return
			case <-ctx.Done():
				return
			}
		}
	}()
}

// StopKeyRefresh stops the background refresh loop.
func (s *TokenSigner) StopKeyRefresh() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stopRefresh != nil {
		close(s.stopRefresh)
		s.stopRefresh = nil
	}
}

// PublicKeys returns the verification material of all active and retiring
// keys (realm-default and per-client) for JWKS publication.
func (s *TokenSigner) PublicKeys() map[string]*rsa.PublicKey {
	s.mu.RLock()
	defer s.mu.RUnlock()

	pub := make(map[string]*rsa.PublicKey)
	for kid, entry := range s.keys {
		if entry.status != domain.RealmKeyStatusActive && entry.status != domain.RealmKeyStatusRetiring {
			continue
		}
		if entry.pubKey != nil {
			pub[kid] = entry.pubKey
		}
	}
	return pub
}

// RealmDefaultKeyID returns the realm-default active key ID.
func (s *TokenSigner) RealmDefaultKeyID() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.defaultKeyID
}
