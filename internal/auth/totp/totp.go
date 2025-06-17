package totp

import (
	"bytes"
	"crypto/rand"
	// "crypto/subtle" // Not directly used, bcrypt handles constant-time for hash comparison
	"encoding/base32"
	"errors" // For bcrypt.ErrMismatchedHashAndPassword
	"fmt"
	"image/png"
	// "net/url" // Not directly used in this final version of code
	"os" // For VerifyRecoveryCode error logging
	"strings"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt" // For hashing recovery codes
)

const (
	// DefaultRecoveryCodeLength is the length of generated recovery codes.
	DefaultRecoveryCodeLength = 10
	// DefaultNumRecoveryCodes is the number of recovery codes to generate.
	DefaultNumRecoveryCodes = 10
)

// GenerateTOTPSecret generates a new TOTP secret key.
// It returns the key and the otpauth:// URI for QR code generation.
func GenerateTOTPSecret(issuer, accountName string) (*otp.Key, string, error) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      issuer,
		AccountName: accountName,
		Period:      30,    // Standard 30 seconds
		SecretSize:  20,    // Standard 20 bytes for base32 secret (produces 32 char base32 string)
		Digits:      otp.DigitsSix, // Standard 6 digits
		Algorithm:   otp.AlgorithmSHA1, // Standard algorithm
	})
	if err != nil {
		return nil, "", fmt.Errorf("failed to generate TOTP key: %w", err)
	}
	// The key.Secret() is the base32 encoded secret. key.URL() is the otpauth URI string.
	return key, key.URL(), nil
}

// GenerateTOTPQRCodeBytes generates a PNG QR code image for the otpauth:// URI.
// Returns PNG image bytes.
func GenerateTOTPQRCodeBytes(otpAuthURI string) ([]byte, error) {
	key, err := otp.NewKeyFromURL(otpAuthURI)
	if err != nil {
		return nil, fmt.Errorf("failed to parse otpauth uri for QR code: %w", err)
	}
	img, err := key.Image(256, 256) // Generate a 256x256 QR code
	if err != nil {
		return nil, fmt.Errorf("failed to generate QR code image: %w", err)
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		return nil, fmt.Errorf("failed to encode QR code image to PNG: %w", err)
	}
	return buf.Bytes(), nil
}

// ValidateTOTPCode validates a TOTP code against the stored secret.
// The secret should be the base32 encoded string from key.Secret().
func ValidateTOTPCode(secret, passcode string) (bool, error) {
	// The pquerna/otp library's totp.Validate handles secrets that are base32 encoded.
	// Ensure the secret is not URL-encoded or otherwise modified from key.Secret().
	// totp.Validate will handle any necessary decoding if the secret is a full otpauth URI,
	// but it's more robust to pass the raw base32 secret string.
	// For this function, 'secret' is assumed to be the raw base32 secret string.
	valid := totp.Validate(passcode, strings.TrimSpace(secret))
	return valid, nil // totp.Validate does not return an error for invalid codes, only for bad inputs (e.g. malformed secret)
}

// GenerateRecoveryCodes generates a set of unique recovery codes.
// Returns the plaintext codes (to show to the user once) and their hashed versions (for storage).
func GenerateRecoveryCodes(count, length int) (plaintextCodes []string, hashedCodes []string, err error) {
	if count <= 0 {
		count = DefaultNumRecoveryCodes
	}
	if length <= 0 {
		length = DefaultRecoveryCodeLength
	}

	plaintextCodes = make([]string, count)
	hashedCodes = make([]string, count)
	// A-Z, a-z, 0-9. Exclude easily confused characters like I, l, 1, O, 0.
	// For simplicity, using a broader charset here. Consider curating it more.
	const charset = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789" // Example charset

	codeMap := make(map[string]bool) // To ensure uniqueness

	for i := 0; i < count; i++ {
		for { // Loop to ensure unique code generation
			b := make([]byte, length)
			if _, randErr := rand.Read(b); randErr != nil {
				return nil, nil, fmt.Errorf("failed to read random bytes for recovery code: %w", randErr)
			}
			for j := range b {
				b[j] = charset[int(b[j])%len(charset)]
			}
			code := string(b)
			if !codeMap[code] { // Check if code is already generated in this batch
				plaintextCodes[i] = code
				codeMap[code] = true
				break
			}
		}

		hashedCode, hashErr := bcrypt.GenerateFromPassword([]byte(plaintextCodes[i]), bcrypt.DefaultCost)
		if hashErr != nil {
			return nil, nil, fmt.Errorf("failed to hash recovery code %d: %w", i+1, hashErr)
		}
		hashedCodes[i] = string(hashedCode)
	}
	return plaintextCodes, hashedCodes, nil
}

// VerifyRecoveryCode checks a provided plaintext recovery code against a list of stored hashed codes.
// It uses bcrypt.CompareHashAndPassword which is inherently slow, mitigating timing attacks on the hash comparison itself.
// Important: If a code is successfully used, it should be invalidated (e.g., removed from the stored list).
// This function only verifies; invalidation is the caller's responsibility.
// Returns true if a match is found, and the index of the matched code.
func VerifyRecoveryCode(hashedCodes []string, providedCode string) (bool, int) {
	providedCodeBytes := []byte(providedCode)
	for i, storedHashedCode := range hashedCodes {
		// bcrypt.CompareHashAndPassword is the correct way to compare bcrypt hashes.
		err := bcrypt.CompareHashAndPassword([]byte(storedHashedCode), providedCodeBytes)
		if err == nil {
			return true, i // Found and matches, return index of used code
		}
		// If bcrypt.ErrMismatchedHashAndPassword, continue checking other stored codes.
		// Any other error during comparison is unexpected and should be logged or handled.
		if !errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
			// Log this unexpected error, as it's not just a mismatch.
			fmt.Fprintf(os.Stderr, "Unexpected error during recovery code comparison (index %d): %v\n", i, err)
		}
	}
	return false, -1 // Not found or no match
}

// Base32Secret returns the base32 encoded string of the secret from an otp.Key.
// This is what should be stored persistently for TOTP validation.
func Base32Secret(key *otp.Key) string {
    return key.Secret()
}
