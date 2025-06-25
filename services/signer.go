package services

import (
	"errors"
	"fmt"

	"github.com/golang-jwt/jwt/v5"
)

var ErrInvalidKeyID = errors.New("invalid key id")

type TokenSignerFunc func(claims jwt.Claims) (string, error)

type TokenSigner struct {
	keys map[string]TokenSignerFunc
}

// NewTokenSigner creates a new Signer instance
func NewTokenSigner() *TokenSigner {
	return &TokenSigner{
		keys: make(map[string]TokenSignerFunc),
	}
}

func (s *TokenSigner) AddKeySigner(secretKey string) {
	s.keys["default"] = func(claims jwt.Claims) (string, error) {
		// Create a new token object, specifying signing method and the claims
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

		// Sign and get the complete encoded token as a string using the secret
		tokenString, err := token.SignedString([]byte(secretKey))
		if err != nil {
			return "", fmt.Errorf("failed to sign token: %w", err)
		}

		return tokenString, nil
	}
}

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
