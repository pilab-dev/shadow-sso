package services_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/pilab-dev/shadow-sso/domain"
	mock_domain "github.com/pilab-dev/shadow-sso/domain/mocks"
	pkgcrypto "github.com/pilab-dev/shadow-sso/pkg/crypto"
	"github.com/pilab-dev/shadow-sso/services"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func encryptedRealmKey(t *testing.T, encKey []byte, id, clientID string, status domain.RealmKeyStatus, priority int) *domain.RealmKey {
	t.Helper()

	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	pemData := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privKey),
	})
	encrypted, err := pkgcrypto.EncryptAESGCM(encKey, string(pemData))
	require.NoError(t, err)

	return &domain.RealmKey{
		ID:         id,
		Type:       "RSA",
		ClientID:   clientID,
		Status:     status,
		Priority:   priority,
		PrivateKey: encrypted,
	}
}

func TestSignerJWKSService_PublishesActiveAndRetiringKeys(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	encKey := make([]byte, 32)
	_, err := rand.Read(encKey)
	require.NoError(t, err)

	mockRepo := mock_domain.NewMockRealmKeysRepository(ctrl)
	mockRepo.EXPECT().ListAllKeys(gomock.Any()).Return([]*domain.RealmKey{
		encryptedRealmKey(t, encKey, "realm-active", "", domain.RealmKeyStatusActive, 10),
		encryptedRealmKey(t, encKey, "client-active", "client-1", domain.RealmKeyStatusActive, 10),
		encryptedRealmKey(t, encKey, "realm-retiring", "", domain.RealmKeyStatusRetiring, 5),
		encryptedRealmKey(t, encKey, "realm-revoked", "", domain.RealmKeyStatusRevoked, 0),
	}, nil)

	signer := services.NewTokenSigner()
	require.NoError(t, signer.LoadFromRepository(context.Background(), mockRepo, encKey))
	assert.Equal(t, "realm-active", signer.RealmDefaultKeyID())

	jwksSvc := services.NewJWKSServiceFromSigner(signer)
	jwks, err := jwksSvc.GetPublicJWKS(context.Background())
	require.NoError(t, err)

	published := make(map[string]bool)
	for _, key := range jwks.Keys {
		published[key.Kid] = true
		assert.Equal(t, "RSA", key.Kty)
		assert.Equal(t, "RS256", key.Alg)
		assert.Equal(t, "sig", key.Use)
		assert.NotEmpty(t, key.N)
		assert.NotEmpty(t, key.E)
	}

	assert.True(t, published["realm-active"], "realm-default active key must be published")
	assert.True(t, published["client-active"], "per-client active key must be published")
	assert.True(t, published["realm-retiring"], "retiring key must stay published for verification")
	assert.False(t, published["realm-revoked"], "revoked key must be excluded from JWKS")
}

func TestSignerJWKSService_GetSigningKey(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	encKey := make([]byte, 32)
	_, err := rand.Read(encKey)
	require.NoError(t, err)

	mockRepo := mock_domain.NewMockRealmKeysRepository(ctrl)
	mockRepo.EXPECT().ListAllKeys(gomock.Any()).Return([]*domain.RealmKey{
		encryptedRealmKey(t, encKey, "realm-active", "", domain.RealmKeyStatusActive, 10),
	}, nil)

	signer := services.NewTokenSigner()
	require.NoError(t, signer.LoadFromRepository(context.Background(), mockRepo, encKey))

	jwksSvc := services.NewJWKSServiceFromSigner(signer)
	kid, material := jwksSvc.GetSigningKey()
	assert.Equal(t, "realm-active", kid)
	assert.NotNil(t, material)
}

func TestSignerJWKSService_NoKeysReturnsError(t *testing.T) {
	signer := services.NewTokenSigner()
	jwksSvc := services.NewJWKSServiceFromSigner(signer)

	_, err := jwksSvc.GetPublicJWKS(context.Background())
	require.Error(t, err)
}
