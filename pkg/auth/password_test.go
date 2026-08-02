package pkgauth_test

import (
	"testing"

	"github.com/pilab-dev/shadow-sso/domain"
	pkgauth "github.com/pilab-dev/shadow-sso/pkg/auth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPasswordPolicyFromRealm_NilSettingsYieldsEmptyPolicy(t *testing.T) {
	p := pkgauth.PasswordPolicyFromRealm(nil)
	assert.Equal(t, pkgauth.PasswordPolicy{}, p)
}

func TestPasswordPolicyFromRealm_MapsAllFields(t *testing.T) {
	s := &domain.RealmSettings{
		PasswordMinLength:    10,
		PasswordMaxLength:    64,
		PasswordLowerCase:    1,
		PasswordUpperCase:    1,
		PasswordDigits:       1,
		PasswordSpecialChars: 1,
	}
	p := pkgauth.PasswordPolicyFromRealm(s)
	assert.Equal(t, 10, p.MinLength)
	assert.Equal(t, 64, p.MaxLength)
	assert.Equal(t, 1, p.LowerCase)
	assert.Equal(t, 1, p.UpperCase)
	assert.Equal(t, 1, p.Digits)
	assert.Equal(t, 1, p.SpecialChars)
}

func TestValidatePassword_EmptyPolicyAcceptsAnything(t *testing.T) {
	assert.NoError(t, pkgauth.ValidatePassword("", pkgauth.PasswordPolicy{}))
	assert.NoError(t, pkgauth.ValidatePassword("a", pkgauth.PasswordPolicy{}))
}

func TestValidatePassword_TooShort(t *testing.T) {
	err := pkgauth.ValidatePassword("short", pkgauth.PasswordPolicy{MinLength: 8})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "at least 8 characters")
}

func TestValidatePassword_MultibyteCountsRunes(t *testing.T) {
	// "passwörd" is 9 bytes but only 8 runes: a MinLength of 9 must reject it
	// because length is measured in runes, not bytes.
	err := pkgauth.ValidatePassword("passwörd", pkgauth.PasswordPolicy{MinLength: 9})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "at least 9 characters")
}

func TestValidatePassword_TooLong(t *testing.T) {
	err := pkgauth.ValidatePassword("this-password-is-way-too-long", pkgauth.PasswordPolicy{MaxLength: 10})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "at most 10 characters")
}

func TestValidatePassword_MissingLowercase(t *testing.T) {
	err := pkgauth.ValidatePassword("UPPER123", pkgauth.PasswordPolicy{LowerCase: 1})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "lowercase")
}

func TestValidatePassword_MissingUppercase(t *testing.T) {
	err := pkgauth.ValidatePassword("lower123", pkgauth.PasswordPolicy{UpperCase: 1})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "uppercase")
}

func TestValidatePassword_MissingDigits(t *testing.T) {
	err := pkgauth.ValidatePassword("LowerUpper", pkgauth.PasswordPolicy{Digits: 2})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "digit")
}

func TestValidatePassword_MissingSpecialChars(t *testing.T) {
	err := pkgauth.ValidatePassword("LowerUpper123", pkgauth.PasswordPolicy{SpecialChars: 1})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "special")
}

func TestValidatePassword_MeetsAllRequirements(t *testing.T) {
	policy := pkgauth.PasswordPolicy{
		MinLength:    8,
		MaxLength:    32,
		LowerCase:    1,
		UpperCase:    1,
		Digits:       1,
		SpecialChars: 1,
	}
	assert.NoError(t, pkgauth.ValidatePassword("Passw0rd!", policy))
}

func TestValidatePassword_FirstViolationWins(t *testing.T) {
	err := pkgauth.ValidatePassword("short", pkgauth.PasswordPolicy{MinLength: 8, UpperCase: 1})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "at least 8 characters")
}
