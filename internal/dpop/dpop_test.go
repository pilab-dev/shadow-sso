package dpop

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func makeProof(t *testing.T, priv *rsa.PrivateKey, method, htu string) string {
	t.Helper()
	jwk := map[string]string{
		"kty": "RSA",
		"n":   base64.RawURLEncoding.EncodeToString(priv.PublicKey.N.Bytes()),
		"e":   base64.RawURLEncoding.EncodeToString(bigBytes(priv.PublicKey.E)),
	}
	header := map[string]interface{}{
		"typ": "dpop+jwt",
		"alg": "RS256",
		"jwk": jwk,
	}
	claims := jwt.MapClaims{
		"jti": "test-jti",
		"htm": method,
		"htu": htu,
		"iat": time.Now().Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header = header
	s, err := token.SignedString(priv)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func bigBytes(n int) []byte {
	if n == 65537 {
		return []byte{1, 0, 1}
	}
	return []byte{byte(n)}
}

func TestVerifyProof(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	requireNoErr(t, err)
	htu := "https://issuer.example/token"
	proof := makeProof(t, priv, "POST", htu)
	jkt, err := VerifyProof(proof, "POST", htu, "", time.Now())
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if jkt == "" {
		t.Fatal("empty jkt")
	}
	// mismatched method
	if _, err := VerifyProof(proof, "GET", htu, "", time.Now()); err == nil {
		t.Fatal("expected method mismatch")
	}
}

func TestAccessTokenHash(t *testing.T) {
	h := AccessTokenHash("abc")
	if h == "" {
		t.Fatal("empty hash")
	}
}

func requireNoErr(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
