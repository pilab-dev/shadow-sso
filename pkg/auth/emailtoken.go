package pkgauth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
)

// NewEmailToken returns a URL-safe random token (to be sent by email) and its SHA-256 hex digest
// (the only form that is stored). A database leak therefore does not expose usable reset or
// verification links.
func NewEmailToken() (token, digest string, err error) {
	b := make([]byte, 32)
	if _, err = rand.Read(b); err != nil {
		return "", "", err
	}
	token = base64.RawURLEncoding.EncodeToString(b)
	return token, HashEmailToken(token), nil
}

// HashEmailToken returns the stored form of an emailed token.
func HashEmailToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}
