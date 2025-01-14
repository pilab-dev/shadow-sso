package ssso

import (
	"errors"

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

func (s *TokenSigner) Sign(claims jwt.Claims, keyID string) (string, error) {
	if signer, ok := s.keys[keyID]; ok {
		return signer(claims)
	}

	return "", ErrInvalidKeyID
}
