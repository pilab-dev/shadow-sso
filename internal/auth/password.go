package auth

import (
	"fmt"
	"github.com/pilab-dev/shadow-sso/services" // For services.PasswordHasher interface
	"golang.org/x/crypto/bcrypt"
)

// BcryptPasswordHasher implements the services.PasswordHasher interface using bcrypt.
type BcryptPasswordHasher struct {
	Cost int
}

// NewBcryptPasswordHasher creates a new BcryptPasswordHasher.
// Default cost is bcrypt.DefaultCost if cost <= 0.
func NewBcryptPasswordHasher(cost int) *BcryptPasswordHasher {
	if cost <= 0 {
		cost = bcrypt.DefaultCost
	}
	return &BcryptPasswordHasher{Cost: cost}
}

// Hash generates a bcrypt hash for the given password.
func (h *BcryptPasswordHasher) Hash(password string) (string, error) {
	hashedBytes, err := bcrypt.GenerateFromPassword([]byte(password), h.Cost)
	if err != nil {
		return "", fmt.Errorf("bcrypt hash generation failed: %w", err)
	}
	return string(hashedBytes), nil
}

// Verify compares a bcrypt hashed password with its possible plaintext equivalent.
// Returns nil on success, or an error (e.g., bcrypt.ErrMismatchedHashAndPassword) on failure.
func (h *BcryptPasswordHasher) Verify(hashedPassword, password string) error {
	return bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
}

// Ensure it implements the interface
var _ services.PasswordHasher = (*BcryptPasswordHasher)(nil)
