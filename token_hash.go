package ssso

import (
	"crypto/sha256"
	"encoding/hex"
)

func HashToken(token string) string {
	hasher := sha256.New()
	hasher.Write([]byte(token))
	hashedBytes := hasher.Sum(nil)
	return hex.EncodeToString(hashedBytes)
}
