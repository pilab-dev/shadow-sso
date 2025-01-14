package cache

import (
	"crypto/sha256"
	"encoding/hex"
)

// HashToken hashes a token string, this will makes the token much shorter.
// The shorter token can be found faster in the cache.
func HashToken(token string) string {
	hasher := sha256.New()
	hasher.Write([]byte(token))
	hashedBytes := hasher.Sum(nil)
	return hex.EncodeToString(hashedBytes)
}
