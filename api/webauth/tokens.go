package webauth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
)

// newEmailToken returns a URL-safe random token (sent by email) and its SHA-256 hex digest
// (stored in the database). Only the digest is persisted so a database leak does not expose
// usable reset/verification links.
func newEmailToken() (token, digest string, err error) {
	b := make([]byte, 32)
	if _, err = rand.Read(b); err != nil {
		return "", "", err
	}
	token = base64.RawURLEncoding.EncodeToString(b)
	return token, hashEmailToken(token), nil
}

// hashEmailToken returns the stored form of an emailed token.
func hashEmailToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}
