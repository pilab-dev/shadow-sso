package pkgauth

import (
	"fmt"
	"strings"
	"unicode"

	"github.com/pilab-dev/shadow-sso/domain"
	"golang.org/x/crypto/bcrypt"
)

// PasswordPolicy describes the strength requirements a password must satisfy.
// A zero value for any field means that requirement is not enforced.
type PasswordPolicy struct {
	MinLength    int
	MaxLength    int
	LowerCase    int
	UpperCase    int
	Digits       int
	SpecialChars int
}

// PasswordPolicyFromRealm derives a PasswordPolicy from realm settings.
// A nil settings value yields an empty (non-enforcing) policy.
func PasswordPolicyFromRealm(s *domain.RealmSettings) PasswordPolicy {
	if s == nil {
		return PasswordPolicy{}
	}
	return PasswordPolicy{
		MinLength:    s.PasswordMinLength,
		MaxLength:    s.PasswordMaxLength,
		LowerCase:    s.PasswordLowerCase,
		UpperCase:    s.PasswordUpperCase,
		Digits:       s.PasswordDigits,
		SpecialChars: s.PasswordSpecialChars,
	}
}

// ValidatePassword checks password against the policy. It returns nil when the
// password satisfies every configured requirement, otherwise a descriptive
// error naming the first violated requirement.
func ValidatePassword(password string, p PasswordPolicy) error {
	if p.MinLength > 0 && len([]rune(password)) < p.MinLength {
		return fmt.Errorf("password must be at least %d characters long", p.MinLength)
	}
	if p.MaxLength > 0 && len([]rune(password)) > p.MaxLength {
		return fmt.Errorf("password must be at most %d characters long", p.MaxLength)
	}
	if p.LowerCase > 0 && countCharClass(password, isLower) < p.LowerCase {
		return fmt.Errorf("password must contain at least %d lowercase letter(s)", p.LowerCase)
	}
	if p.UpperCase > 0 && countCharClass(password, isUpper) < p.UpperCase {
		return fmt.Errorf("password must contain at least %d uppercase letter(s)", p.UpperCase)
	}
	if p.Digits > 0 && countCharClass(password, isDigit) < p.Digits {
		return fmt.Errorf("password must contain at least %d digit(s)", p.Digits)
	}
	if p.SpecialChars > 0 && countCharClass(password, isSpecial) < p.SpecialChars {
		return fmt.Errorf("password must contain at least %d special character(s)", p.SpecialChars)
	}
	return nil
}

type charClass func(rune) bool

func isLower(r rune) bool    { return unicode.IsLower(r) }
func isUpper(r rune) bool    { return unicode.IsUpper(r) }
func isDigit(r rune) bool    { return unicode.IsDigit(r) }
func isSpecial(r rune) bool  { return !unicode.IsLetter(r) && !unicode.IsDigit(r) && !strings.ContainsRune(" \t\r\n", r) }

func countCharClass(s string, class charClass) int {
	n := 0
	for _, r := range s {
		if class(r) {
			n++
		}
	}
	return n
}

// BcryptPasswordHasher implements the domain.PasswordHasher interface using bcrypt.
type BcryptPasswordHasher struct {
	Cost int
}

// NewBcryptPasswordHasher creates a new BcryptPasswordHasher.
// Default cost is bcrypt.DefaultCost if cost <= 0.
func NewBcryptPasswordHasher(cost int) domain.PasswordHasher {
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
