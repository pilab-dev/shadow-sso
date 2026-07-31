package services

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"

	"github.com/golang-jwt/jwt/v5"
)

var ErrInvalidKeyID = errors.New("invalid key id")
var ErrInvalidRSAKey = errors.New("invalid RSA key")

type TokenSignerFunc func(claims jwt.Claims) (string, error)

type TokenSigner struct {
	keys        map[string]TokenSignerFunc
	rsaPrivKey  *rsa.PrivateKey
	rsaPubKey   *rsa.PublicKey
	hs256Secret []byte
}

// NewTokenSigner creates a new Signer instance
func NewTokenSigner() *TokenSigner {
	return &TokenSigner{
		keys: make(map[string]TokenSignerFunc),
	}
}

func (s *TokenSigner) AddKeySigner(secretKey string) {
	s.hs256Secret = []byte(secretKey)
	s.keys["default"] = func(claims jwt.Claims) (string, error) {
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

		tokenString, err := token.SignedString([]byte(secretKey))
		if err != nil {
			return "", fmt.Errorf("failed to sign token: %w", err)
		}

		return tokenString, nil
	}
}

func (s *TokenSigner) AddRSASigner(keyPath string) error {
	keyData, err := os.ReadFile(keyPath)
	if err != nil {
		return fmt.Errorf("failed to read RSA key file: %w", err)
	}

	block, _ := pem.Decode(keyData)
	if block == nil {
		return ErrInvalidRSAKey
	}

	privKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		parsedKey, errParse := x509.ParsePKCS8PrivateKey(block.Bytes)
		if errParse != nil {
			return fmt.Errorf("failed to parse RSA private key: %w (also tried PKCS8: %w)", err, errParse)
		}
		rsaKey, ok := parsedKey.(*rsa.PrivateKey)
		if !ok {
			return ErrInvalidRSAKey
		}
		privKey = rsaKey
	}

	if privKey.N.BitLen() < 2048 {
		return fmt.Errorf("RSA key too small: %d bits (minimum 2048)", privKey.N.BitLen())
	}

	s.rsaPrivKey = privKey
	s.rsaPubKey = &privKey.PublicKey

	s.keys["rsa-default"] = func(claims jwt.Claims) (string, error) {
		token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		token.Header["kid"] = "rsa-default"
		tokenString, err := token.SignedString(privKey)
		if err != nil {
			return "", fmt.Errorf("failed to sign token with RSA: %w", err)
		}
		return tokenString, nil
	}

	s.keys["default"] = s.keys["rsa-default"]

	return nil
}

func (s *TokenSigner) GetRSAPublicKey() *rsa.PublicKey {
	return s.rsaPubKey
}

func (s *TokenSigner) GetRSAPrivateKey() *rsa.PrivateKey {
	return s.rsaPrivKey
}

func (s *TokenSigner) HasRSASigner() bool {
	return s.rsaPrivKey != nil
}

func (s *TokenSigner) GetDefaultSigningMethod() jwt.SigningMethod {
	if s.rsaPrivKey != nil {
		return jwt.SigningMethodRS256
	}
	return jwt.SigningMethodHS256
}

// Sign signs the given claims with the specified key ID.
func (s *TokenSigner) Sign(claims jwt.Claims, keyID string) (string, error) {
	if keyID == "" { // using default signer
		for _, val := range s.keys {
			if val != nil {
				return val(claims)
			}
		}

		// default signer not found
		return "", ErrInvalidKeyID
	}

	if signer, ok := s.keys[keyID]; ok {
		return signer(claims)
	}

	return "", ErrInvalidKeyID
}

// VerifyToken verifies a JWT signature against the signer's configured keys
// (HS256 via the shared secret, RS256 via the RSA public key) and validates
// standard exp/nbf claims.
func (s *TokenSigner) VerifyToken(tokenString string) (jwt.MapClaims, error) {
	claims := jwt.MapClaims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		switch token.Method.(type) {
		case *jwt.SigningMethodHMAC:
			if s.hs256Secret == nil {
				return nil, errors.New("no HS256 secret configured for verification")
			}
			return s.hs256Secret, nil
		case *jwt.SigningMethodRSA:
			if s.rsaPubKey == nil {
				return nil, errors.New("no RSA public key configured for verification")
			}
			return s.rsaPubKey, nil
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
