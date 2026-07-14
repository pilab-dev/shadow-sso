package services_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/pilab-dev/shadow-sso/services"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func generateTestRSAKey(t *testing.T) (*rsa.PrivateKey, string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "test_key.pem")

	pemData := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
	require.NoError(t, os.WriteFile(keyPath, pemData, 0600))

	return key, keyPath
}

func TestTokenSigner_AddRSASigner(t *testing.T) {
	_, keyPath := generateTestRSAKey(t)

	signer := services.NewTokenSigner()
	err := signer.AddRSASigner(keyPath)

	require.NoError(t, err)
	assert.True(t, signer.HasRSASigner())
	assert.NotNil(t, signer.GetRSAPublicKey())
	assert.Equal(t, jwt.SigningMethodRS256, signer.GetDefaultSigningMethod())
}

func TestTokenSigner_AddRSASigner_InvalidPath(t *testing.T) {
	signer := services.NewTokenSigner()
	err := signer.AddRSASigner("/nonexistent/path/key.pem")

	require.Error(t, err)
	assert.False(t, signer.HasRSASigner())
}

func TestTokenSigner_AddRSASigner_InvalidPEM(t *testing.T) {
	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "invalid_key.pem")
	require.NoError(t, os.WriteFile(keyPath, []byte("not a valid PEM"), 0600))

	signer := services.NewTokenSigner()
	err := signer.AddRSASigner(keyPath)

	require.Error(t, err)
	assert.False(t, signer.HasRSASigner())
}

func TestJWTAlgorithm_RS256(t *testing.T) {
	_, keyPath := generateTestRSAKey(t)

	signer := services.NewTokenSigner()
	require.NoError(t, signer.AddRSASigner(keyPath))

	claims := jwt.MapClaims{
		"sub": "user-123",
		"iss": "test-issuer",
		"aud": "client-123",
	}

	tokenString, err := signer.Sign(claims, "")
	require.NoError(t, err)
	assert.NotEmpty(t, tokenString)

	token, err := jwt.ParseWithClaims(tokenString, &jwt.MapClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			t.Fatalf("unexpected signing method: %v", token.Header["alg"])
		}
		return signer.GetRSAPublicKey(), nil
	})

	require.NoError(t, err)
	assert.True(t, token.Valid)

	parsedClaims, ok := token.Claims.(*jwt.MapClaims)
	require.True(t, ok)
	assert.Equal(t, "user-123", (*parsedClaims)["sub"])
}

func TestJWTAlgorithm_HS256Fallback(t *testing.T) {
	signer := services.NewTokenSigner()
	signer.AddKeySigner("test-secret")

	assert.False(t, signer.HasRSASigner())
	assert.Equal(t, jwt.SigningMethodHS256, signer.GetDefaultSigningMethod())

	claims := jwt.MapClaims{
		"sub": "user-456",
		"iss": "test-issuer",
	}

	tokenString, err := signer.Sign(claims, "")
	require.NoError(t, err)
	assert.NotEmpty(t, tokenString)

	token, err := jwt.ParseWithClaims(tokenString, &jwt.MapClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			t.Fatalf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte("test-secret"), nil
	})

	require.NoError(t, err)
	assert.True(t, token.Valid)
}

func TestJWTAlgorithm_BackwardCompatibility(t *testing.T) {
	_, keyPath := generateTestRSAKey(t)

	signer := services.NewTokenSigner()
	require.NoError(t, signer.AddRSASigner(keyPath))

	hs256Claims := jwt.MapClaims{
		"sub": "old-user",
		"iss": "test-issuer",
	}
	hs256Token := jwt.NewWithClaims(jwt.SigningMethodHS256, hs256Claims)
	hs256String, err := hs256Token.SignedString([]byte("old-secret"))
	require.NoError(t, err)

	rs256Claims := jwt.MapClaims{
		"sub": "new-user",
		"iss": "test-issuer",
	}
	rs256String, err := signer.Sign(rs256Claims, "")
	require.NoError(t, err)

	assert.NotEqual(t, hs256String, rs256String)

	token, err := jwt.ParseWithClaims(rs256String, &jwt.MapClaims{}, func(token *jwt.Token) (interface{}, error) {
		return signer.GetRSAPublicKey(), nil
	})
	require.NoError(t, err)
	assert.True(t, token.Valid)
}

func TestTokenSigner_SmallRSAKey(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	require.NoError(t, err)

	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "small_key.pem")
	pemData := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
	require.NoError(t, os.WriteFile(keyPath, pemData, 0600))

	signer := services.NewTokenSigner()
	err = signer.AddRSASigner(keyPath)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "too small")
}