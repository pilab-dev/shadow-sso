package services

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"

	"github.com/pilab-dev/shadow-sso/domain" // Added domain import
	"github.com/rs/zerolog/log"
)

// PKCEService handles PKCE validation
type PKCEService struct {
	pkceRepo domain.PkceRepository
}

// NewPKCEService creates a new PKCE service instance
func NewPKCEService(pkceRepo domain.PkceRepository) *PKCEService {
	return &PKCEService{
		pkceRepo: pkceRepo,
	}
}

// ValidateCodeVerifier validates the PKCE code verifier against the stored challenge
func (s *PKCEService) ValidateCodeVerifier(ctx context.Context, code, verifier string) error {
	challenge, err := s.pkceRepo.GetCodeChallenge(ctx, code)
	if err != nil {
		return fmt.Errorf("failed to get code challenge: %w", err)
	}
	// GetCodeChallenge might return "", nil for not found in some implementations.
	// We should treat an empty challenge as a failure.
	if challenge == "" {
		return fmt.Errorf("code challenge not found or empty for code: %s", code)
	}

	if !ValidatePKCEChallenge(challenge, verifier) {
		return fmt.Errorf("invalid code verifier")
	}

	// Clean up the challenge after successful validation
	if err := s.pkceRepo.DeleteCodeChallenge(ctx, code); err != nil {
		log.Error().Err(err).Msg("failed to delete code challenge")
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

func (s *PKCEService) SavePKCEChallenge(ctx context.Context, code, challenge string) error {
	return s.pkceRepo.SaveCodeChallenge(ctx, code, challenge)
}
