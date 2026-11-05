package services

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"

	"github.com/pilab-dev/shadow-sso/domain" // Added domain import
	"github.com/rs/zerolog/log"
)

// PKCEService handles PKCE validation
type defaultPKCEService struct {
	pkceRepo domain.PkceRepository
}

// newDefaultPKCEService creates a new PKCE service instance (internal constructor).
func newDefaultPKCEService(pkceRepo domain.PkceRepository) PKCEService {
	return &defaultPKCEService{
		pkceRepo: pkceRepo,
	}
}

// NewPKCEService creates a new PKCE service instance (public constructor for backward compatibility).
func NewPKCEService(pkceRepo domain.PkceRepository) *defaultPKCEService {
	return &defaultPKCEService{
		pkceRepo: pkceRepo,
	}
}

// ValidateCodeVerifier validates the PKCE code verifier against the stored challenge
func (s *defaultPKCEService) ValidateCodeVerifier(ctx context.Context, code, verifier string) error {
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

// ValidatePKCEChallenge validates a code verifier against a code challenge using S256 only.
// The "plain" method is not supported as it is insecure (RFC 7636 recommends S256).
func ValidatePKCEChallenge(challenge, verifier string) bool {
	if len(verifier) < 43 || len(verifier) > 128 {
		return false
	}
	h := sha256.New()
	h.Write([]byte(verifier))
	calculatedChallenge := base64.RawURLEncoding.EncodeToString(h.Sum(nil))
	return subtle.ConstantTimeCompare([]byte(challenge), []byte(calculatedChallenge)) == 1
}

// HasCodeChallenge reports whether a PKCE challenge is bound to the code, in
// which case the token request must prove possession of the code verifier.
func (s *defaultPKCEService) HasCodeChallenge(ctx context.Context, code string) bool {
	challenge, err := s.pkceRepo.GetCodeChallenge(ctx, code)
	return err == nil && challenge != ""
}

func (s *defaultPKCEService) SavePKCEChallenge(ctx context.Context, code, challenge string) error {
	return s.pkceRepo.SaveCodeChallenge(ctx, code, challenge)
}
