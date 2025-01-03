package api

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
)

// PKCEService handles PKCE (Proof Key for Code Exchange) validation
type PKCEService struct {
	oauthRepo OAuthRepository
}

// NewPKCEService creates a new PKCE service instance
func NewPKCEService(oauthRepo OAuthRepository) *PKCEService {
	return &PKCEService{
		oauthRepo: oauthRepo,
	}
}

// ValidateCodeVerifier validates the PKCE code verifier against the stored challenge
func (s *PKCEService) ValidateCodeVerifier(code, verifier string) error {
	challenge, err := s.oauthRepo.GetCodeChallenge(code)
	if err != nil {
		return fmt.Errorf("failed to get code challenge: %w", err)
	}

	if !ValidatePKCEChallenge(challenge, verifier) {
		return fmt.Errorf("invalid code verifier")
	}

	return nil
}

// ValidatePKCEChallenge validates a code verifier against a code challenge
func ValidatePKCEChallenge(challenge, verifier string) bool {
	// For plain method
	if challenge == verifier {
		return true
	}

	// For S256 method
	h := sha256.New()
	h.Write([]byte(verifier))
	calculatedChallenge := base64.RawURLEncoding.EncodeToString(h.Sum(nil))
	return challenge == calculatedChallenge
}
