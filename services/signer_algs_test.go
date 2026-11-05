package services_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/pilab-dev/shadow-sso/domain"
	mock_domain "github.com/pilab-dev/shadow-sso/domain/mocks"
	pkgcrypto "github.com/pilab-dev/shadow-sso/pkg/crypto"
	"github.com/pilab-dev/shadow-sso/services"
)

func sealedKey(t *testing.T, encKey []byte, id, keyType string, prio int, block *pem.Block) *domain.RealmKey {
	t.Helper()
	enc, err := pkgcrypto.EncryptAESGCM(encKey, string(pem.EncodeToMemory(block)))
	require.NoError(t, err)
	return &domain.RealmKey{ID: id, Type: keyType, Status: domain.RealmKeyStatusActive, Priority: prio, PrivateKey: enc}
}

func TestSignerSupportsECEdDSAAndPSKeys(t *testing.T) {
	encKey := make([]byte, 32)
	_, err := rand.Read(encKey)
	require.NoError(t, err)

	ec, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)
	ecDER, err := x509.MarshalECPrivateKey(ec)
	require.NoError(t, err)
	_, edPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	edDER, err := x509.MarshalPKCS8PrivateKey(edPriv)
	require.NoError(t, err)
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	ctrl := gomock.NewController(t)
	repo := mock_domain.NewMockRealmKeysRepository(ctrl)
	repo.EXPECT().ListAllKeys(gomock.Any()).Return([]*domain.RealmKey{
		sealedKey(t, encKey, "ec1", "EC", 1, &pem.Block{Type: "EC PRIVATE KEY", Bytes: ecDER}),
		sealedKey(t, encKey, "ed1", "EdDSA", 2, &pem.Block{Type: "PRIVATE KEY", Bytes: edDER}),
		sealedKey(t, encKey, "ps1", "PS256", 3, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(rsaKey)}),
	}, nil)

	signer := services.NewTokenSigner()
	require.NoError(t, signer.LoadFromRepository(context.Background(), repo, encKey))

	for kid, alg := range map[string]string{"ec1": "ES384", "ed1": "EdDSA", "ps1": "PS256"} {
		tok, err := signer.Sign(jwt.MapClaims{"sub": "u", "exp": time.Now().Add(time.Minute).Unix()}, kid)
		require.NoError(t, err, kid)
		parsed, _, err := jwt.NewParser().ParseUnverified(tok, jwt.MapClaims{})
		require.NoError(t, err)
		assert.Equal(t, alg, parsed.Method.Alg())

		claims, err := signer.VerifyAsymmetricToken(tok)
		require.NoError(t, err, kid)
		assert.Equal(t, "u", claims["sub"])
	}
	assert.Equal(t, []string{"ES384", "EdDSA", "PS256"}, signer.SigningAlgorithms())

	// A token whose alg does not match its kid's key must be rejected.
	forged := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{"sub": "u", "exp": time.Now().Add(time.Minute).Unix()})
	forged.Header["kid"] = "ec1"
	forgedKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	forgedTok, err := forged.SignedString(forgedKey)
	require.NoError(t, err)
	_, err = signer.VerifyAsymmetricToken(forgedTok)
	assert.Error(t, err)

	set := services.NewJWKSServiceFromSigner(signer).(interface{ GetJWKS() services.JSONWebKeySet }).GetJWKS()
	byKid := map[string]services.JSONWebKey{}
	for _, k := range set.Keys {
		byKid[k.Kid] = k
	}
	assert.Equal(t, "EC", byKid["ec1"].Kty)
	assert.Equal(t, "P-384", byKid["ec1"].Crv)
	assert.Len(t, byKid["ec1"].X, 64)
	assert.Equal(t, "OKP", byKid["ed1"].Kty)
	assert.Equal(t, "Ed25519", byKid["ed1"].Crv)
	assert.Equal(t, "RSA", byKid["ps1"].Kty)
	assert.Equal(t, "PS256", byKid["ps1"].Alg)
}
