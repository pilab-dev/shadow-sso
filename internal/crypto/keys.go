package crypto

import (
	"crypto/rand"
	"crypto/rsa"
)

// GenerateRSAKey generates a new RSA private key. It returns the key and any error that
// occurred during the generation process.
func GenerateRSAKey() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, 2048)
}
