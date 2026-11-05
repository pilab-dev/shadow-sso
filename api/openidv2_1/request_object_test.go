package openidv2_1_test

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"math/big"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/pilab-dev/shadow-sso/domain"
)

func TestAuthorize_RequestObject(t *testing.T) {
	router, repo, _ := setupPARTest(t)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	cli := &domain.Client{
		ID: "jar", RequireSignedRequestObject: true,
		JWKS: &domain.JWKS{Keys: []domain.JSONWebKey{{
			Kid: "k1", Kty: "RSA", Use: "sig",
			N: base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
			E: base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
		}}},
	}
	repo.EXPECT().GetClient(gomock.Any(), "jar").AnyTimes().Return(cli, nil)

	sign := func(aud string) string {
		tok := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
			"iss": "jar", "aud": aud, "client_id": "jar", "exp": time.Now().Add(time.Minute).Unix(),
			"response_type": "code", "scope": "openid", "redirect_uri": "http://localhost/cb",
		})
		tok.Header["kid"] = "k1"
		s, err := tok.SignedString(key)
		require.NoError(t, err)
		return s
	}

	// unsigned direct request is refused for a client requiring request objects
	w := getAuthorize(router, parForm("jar"))
	require.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "signed request object required")

	// wrong audience is rejected
	q := url.Values{"client_id": {"jar"}, "request": {sign("http://evil")}}
	w = getAuthorize(router, q)
	require.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "invalid request object")

	// a valid object passes request-object verification
	q = url.Values{"client_id": {"jar"}, "request": {sign("http://localhost")}}
	w = getAuthorize(router, q)
	assert.NotContains(t, w.Body.String(), "invalid request object")
	assert.NotContains(t, w.Body.String(), "signed request object required")
}
