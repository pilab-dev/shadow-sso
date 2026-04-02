package services

import (
	"crypto/rsa"
	"errors"
	"fmt"

	"github.com/golang-jwt/jwt/v5"
)

var ErrInvalidKeyID = errors.New("invalid key id")

type TokenSignerFunc func(claims jwt.Claims) (string, error)

type TokenSigner struct {
	keys map[string]TokenSignerFunc
}

func NewTokenSigner() *TokenSigner {
	return &TokenSigner{
		keys: make(map[string]TokenSignerFunc),
	}
}

func (s *TokenSigner) AddKeySigner(secretKey string) {
	s.keys["default"] = func(claims jwt.Claims) (string, error) {
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		tokenString, err := token.SignedString([]byte(secretKey))
		if err != nil {
			return "", fmt.Errorf("failed to sign token: %w", err)
		}
		return tokenString, nil
	}
}

func (s *TokenSigner) AddRSASigner(keyID string, privateKey *rsa.PrivateKey) {
	s.keys[keyID] = func(claims jwt.Claims) (string, error) {
		token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		token.Header["kid"] = keyID
		tokenString, err := token.SignedString(privateKey)
		if err != nil {
			return "", fmt.Errorf("failed to sign token with RSA key %s: %w", keyID, err)
		}
		return tokenString, nil
	}
}

func (s *TokenSigner) Sign(claims jwt.Claims, keyID string) (string, error) {
	if keyID == "" {
		for _, val := range s.keys {
			if val != nil {
				return val(claims)
			}
		}
		return "", ErrInvalidKeyID
	}

	if signer, ok := s.keys[keyID]; ok {
		return signer(claims)
	}

	return "", ErrInvalidKeyID
}
