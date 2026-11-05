package domain_test

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pilab-dev/shadow-sso/domain"
)

func TestVerifyRequestObject(t *testing.T) {
	client, key := assertionClient(t)
	const issuer = "https://sso.example.com"
	sign := func(mutate func(jwt.MapClaims), k interface{}, m jwt.SigningMethod) string {
		claims := jwt.MapClaims{
			"iss": "client-1", "aud": issuer, "client_id": "client-1",
			"exp":           time.Now().Add(time.Minute).Unix(),
			"response_type": "code", "scope": "openid", "redirect_uri": "https://app/cb",
			"authorization_details": []map[string]any{{"type": "payment"}},
		}
		if mutate != nil {
			mutate(claims)
		}
		tok := jwt.NewWithClaims(m, claims)
		tok.Header["kid"] = "k1"
		s, err := tok.SignedString(k)
		require.NoError(t, err)
		return s
	}

	params, err := domain.VerifyRequestObject(client, sign(nil, key, jwt.SigningMethodRS256), issuer)
	require.NoError(t, err)
	assert.Equal(t, "openid", params["scope"])
	assert.JSONEq(t, `[{"type":"payment"}]`, params["authorization_details"])

	_, err = domain.VerifyRequestObject(client, sign(func(c jwt.MapClaims) { c["aud"] = "https://evil" }, key, jwt.SigningMethodRS256), issuer)
	assert.Error(t, err, "wrong audience")
	_, err = domain.VerifyRequestObject(client, sign(func(c jwt.MapClaims) { c["client_id"] = "other" }, key, jwt.SigningMethodRS256), issuer)
	assert.Error(t, err, "client_id mismatch")
	_, err = domain.VerifyRequestObject(client, sign(nil, jwt.UnsafeAllowNoneSignatureType, jwt.SigningMethodNone), issuer)
	assert.Error(t, err, "alg none")
	_, err = domain.VerifyRequestObject(client, sign(nil, []byte("secret"), jwt.SigningMethodHS256), issuer)
	assert.Error(t, err, "hmac")
}
