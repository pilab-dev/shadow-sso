package domain_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"math/big"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pilab-dev/shadow-sso/domain"
)

const assertionAud = "https://sso.example.com/oauth2/token"

func assertionClient(t *testing.T) (*domain.Client, *rsa.PrivateKey) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	return &domain.Client{
		ID: "client-1",
		JWKS: &domain.JWKS{Keys: []domain.JSONWebKey{{
			Kid: "k1", Kty: "RSA", Use: "sig",
			N: base64.RawURLEncoding.EncodeToString(priv.N.Bytes()),
			E: base64.RawURLEncoding.EncodeToString(big.NewInt(int64(priv.E)).Bytes()),
		}}},
	}, priv
}

func signAssertion(t *testing.T, key *rsa.PrivateKey, mutate func(*jwt.RegisteredClaims)) string {
	t.Helper()
	claims := jwt.RegisteredClaims{
		Issuer:    "client-1",
		Subject:   "client-1",
		Audience:  jwt.ClaimStrings{assertionAud},
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Minute)),
		ID:        base64.RawURLEncoding.EncodeToString([]byte(time.Now().String())),
	}
	if mutate != nil {
		mutate(&claims)
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = "k1"
	signed, err := tok.SignedString(key)
	require.NoError(t, err)
	return signed
}

func authenticateAssertion(client *domain.Client, assertion string) error {
	_, err := domain.NewClientJWTAuthenticator(client, assertionAud).Authenticate(context.Background(), client, "client-1",
		map[string][]string{
			"client_assertion":      {assertion},
			"client_assertion_type": {domain.ClientAssertionTypeJWTBearer},
		})
	return err
}

func TestClientJWTAuthenticator(t *testing.T) {
	client, key := assertionClient(t)
	other, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	t.Run("valid assertion is accepted once, replay rejected", func(t *testing.T) {
		assertion := signAssertion(t, key, func(c *jwt.RegisteredClaims) { c.ID = "jti-once" })
		require.NoError(t, authenticateAssertion(client, assertion))
		assert.Error(t, authenticateAssertion(client, assertion))
	})

	cases := map[string]struct {
		key    *rsa.PrivateKey
		mutate func(*jwt.RegisteredClaims)
	}{
		"signed with a key the client did not register": {other, nil},
		"wrong audience": {key, func(c *jwt.RegisteredClaims) { c.Audience = jwt.ClaimStrings{"https://evil.example"} }},
		"wrong subject":  {key, func(c *jwt.RegisteredClaims) { c.Subject = "someone-else" }},
		"wrong issuer":   {key, func(c *jwt.RegisteredClaims) { c.Issuer = "someone-else" }},
		"expired":        {key, func(c *jwt.RegisteredClaims) { c.ExpiresAt = jwt.NewNumericDate(time.Now().Add(-time.Hour)) }},
		"no expiry":      {key, func(c *jwt.RegisteredClaims) { c.ExpiresAt = nil }},
		"lifetime too long": {key, func(c *jwt.RegisteredClaims) {
			c.ExpiresAt = jwt.NewNumericDate(time.Now().Add(time.Hour))
		}},
		"missing jti": {key, func(c *jwt.RegisteredClaims) { c.ID = "" }},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			assert.Error(t, authenticateAssertion(client, signAssertion(t, tc.key, tc.mutate)))
		})
	}

	t.Run("audience may be an array containing the endpoint", func(t *testing.T) {
		assertion := signAssertion(t, key, func(c *jwt.RegisteredClaims) {
			c.ID = "jti-array"
			c.Audience = jwt.ClaimStrings{"other", assertionAud}
		})
		assert.NoError(t, authenticateAssertion(client, assertion))
	})

	t.Run("HMAC assertions are rejected", func(t *testing.T) {
		tok := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{
			Issuer: "client-1", Subject: "client-1", Audience: jwt.ClaimStrings{assertionAud},
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Minute)), ID: "jti-hs",
		})
		signed, err := tok.SignedString([]byte("secret"))
		require.NoError(t, err)
		assert.Error(t, authenticateAssertion(client, signed))
	})

	t.Run("wrong assertion type is rejected", func(t *testing.T) {
		_, err := domain.NewClientJWTAuthenticator(client, assertionAud).Authenticate(context.Background(), client, "client-1",
			map[string][]string{
				"client_assertion":      {signAssertion(t, key, func(c *jwt.RegisteredClaims) { c.ID = "jti-type" })},
				"client_assertion_type": {"jwt"},
			})
		assert.Error(t, err)
	})
}

func TestClientSecretJWTAuthenticator(t *testing.T) {
	secret := []byte("super-secret-value")
	client := &domain.Client{ID: "client-1"}
	sign := func(key []byte, alg jwt.SigningMethod, jti string) string {
		s, err := jwt.NewWithClaims(alg, jwt.RegisteredClaims{
			Issuer: "client-1", Subject: "client-1",
			Audience:  jwt.ClaimStrings{assertionAud},
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Minute)),
			ID:        jti,
		}).SignedString(key)
		require.NoError(t, err)
		return s
	}
	auth := func(a string) error {
		_, err := domain.NewClientSecretJWTAuthenticator(client, secret, assertionAud).Authenticate(
			context.Background(), client, "client-1", map[string][]string{
				"client_assertion":      {a},
				"client_assertion_type": {domain.ClientAssertionTypeJWTBearer},
			})
		return err
	}

	assert.NoError(t, auth(sign(secret, jwt.SigningMethodHS256, "csj-1")))
	assert.NoError(t, auth(sign(secret, jwt.SigningMethodHS512, "csj-2")))
	assert.Error(t, auth(sign([]byte("wrong"), jwt.SigningMethodHS256, "csj-3")))
	replay := sign(secret, jwt.SigningMethodHS256, "csj-4")
	assert.NoError(t, auth(replay))
	assert.Error(t, auth(replay))
}
