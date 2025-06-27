package auth_test

import (
	"crypto/rand"
	"testing"

	"github.com/pilab-dev/shadow-sso/internal/auth"
)

func TestPasswordHasher(t *testing.T) {
	hasher := auth.NewBcryptPasswordHasher(0)

	hash, err := hasher.Hash("password")
	if err != nil {
		t.Errorf("Hash failed: %v", err)
	}
	if err := hasher.Verify(hash, "password"); err != nil {
		t.Errorf("Verify failed: %v", err)
	}

	t.Run("TestTooLongPassword", func(t *testing.T) {
		tooLongPass := make([]byte, 73)
		rand.Read(tooLongPass)

		_, err := hasher.Hash(string(tooLongPass))
		if err == nil {
			t.Errorf("Hash should have failed")
		}
	})
}
