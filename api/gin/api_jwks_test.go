//go:build gin

package sssogin

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/pilab-dev/shadow-sso/key"
	"github.com/stretchr/testify/assert"
)

func TestJWKSHandler_ReturnsJWKS(t *testing.T) {
	router, _, _, mockJWKS, _, _ := setupTestAPI(t) // Uses helper from handlers_test.go

	expectedJWKS := key.JWKS{
		Keys: []key.JWK{
			{Kid: "test-kid", Kty: "RSA", Alg: "RS256", Use: "sig"},
		},
	}

	mockJWKS.GetPublicJWKSFunc = func(ctx context.Context) (key.JWKS, error) {
		return expectedJWKS, nil
	}

	w := performGetRequest(router, "/.well-known/jwks.json", nil) // Uses helper from handlers_test.go

	assert.Equal(t, http.StatusOK, w.Code)

	var respJWKS key.JWKS
	err := json.Unmarshal(w.Body.Bytes(), &respJWKS)
	assert.NoError(t, err)
	assert.Equal(t, expectedJWKS, respJWKS)
}

func TestJWKSHandler_ServiceError(t *testing.T) {
	router, _, _, mockJWKS, _, _ := setupTestAPI(t)

	mockJWKS.GetPublicJWKSFunc = func(ctx context.Context) (key.JWKS, error) {
		return key.JWKS{}, assert.AnError // Using assert.AnError for a generic error
	}

	w := performGetRequest(router, "/.well-known/jwks.json", nil)

	assert.Equal(t, http.StatusInternalServerError, w.Code)

	var respJSON map[string]string
	err := json.Unmarshal(w.Body.Bytes(), &respJSON)
	assert.NoError(t, err)
	assert.Equal(t, "Failed to retrieve JWKS", respJSON["error"])
}
