package server

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pilab-dev/shadow-sso/apps/ssso/config"
	"github.com/pilab-dev/shadow-sso/domain"
	mock_domain "github.com/pilab-dev/shadow-sso/domain/mocks"
	pkgcrypto "github.com/pilab-dev/shadow-sso/pkg/crypto"
	"github.com/pilab-dev/shadow-sso/services"
	mock_services "github.com/pilab-dev/shadow-sso/services/mocks"
	"go.uber.org/mock/gomock"
)

const testEncryptionKey = "0123456789abcdef0123456789abcdef" // 32 bytes

func newRSASigner(t *testing.T) (*services.TokenSigner, []byte) {
	t.Helper()
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}
	path := filepath.Join(t.TempDir(), "private.pem")
	pemData := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privKey)})
	if err := os.WriteFile(path, pemData, 0o600); err != nil {
		t.Fatalf("failed to write RSA key file: %v", err)
	}

	signer := services.NewTokenSigner()
	if err := signer.AddRSASigner(path); err != nil {
		t.Fatalf("failed to add RSA signer: %v", err)
	}
	exported, err := signer.ExportRSAPrivateKeyPEM()
	if err != nil {
		t.Fatalf("failed to export RSA key: %v", err)
	}
	return signer, exported
}

func TestBootstrapRegistrySigner_HS256Only_StaysLegacy(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	signer := services.NewTokenSigner()
	signer.AddKeySigner("test-hs256-secret")
	provider := mock_services.NewMockRepositoryProvider(ctrl)

	cfg := config.Config{
		TokenSigningKey:     "test-hs256-secret",
		ConfigEncryptionKey: testEncryptionKey,
	}
	upgraded := bootstrapRegistrySigner(context.Background(), cfg, provider, signer)

	if upgraded != signer {
		t.Fatal("expected the original signer to be returned")
	}
	if upgraded.IsRegistryBacked() {
		t.Fatal("HS256-only config must stay on the legacy signer")
	}
}

func TestBootstrapRegistrySigner_ShortEncryptionKey_StaysLegacy(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	signer, _ := newRSASigner(t)
	provider := mock_services.NewMockRepositoryProvider(ctrl)

	cfg := config.Config{ConfigEncryptionKey: "too-short"}
	upgraded := bootstrapRegistrySigner(context.Background(), cfg, provider, signer)

	if upgraded != signer {
		t.Fatal("expected the original signer to be returned")
	}
	if upgraded.IsRegistryBacked() {
		t.Fatal("signer must stay legacy with a non-32-byte encryption key")
	}
}

func TestBootstrapRegistrySigner_EmptyRegistry_SeedsRealmDefaultKey(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	signer, privPEM := newRSASigner(t)

	repo := mock_domain.NewMockRealmKeysRepository(ctrl)
	provider := mock_services.NewMockRepositoryProvider(ctrl)
	provider.EXPECT().RealmKeysRepository(gomock.Any()).Return(repo)

	var seeded *domain.RealmKey
	gomock.InOrder(
		repo.EXPECT().ListAllKeys(gomock.Any()).Return(nil, nil),
		repo.EXPECT().SaveRealmKey(gomock.Any(), gomock.Any()).DoAndReturn(func(_ context.Context, key *domain.RealmKey) error {
			seeded = key
			key.ID = "realm-default-1"
			return nil
		}),
		repo.EXPECT().ListAllKeys(gomock.Any()).DoAndReturn(func(_ context.Context) ([]*domain.RealmKey, error) {
			return []*domain.RealmKey{seeded}, nil
		}),
	)

	cfg := config.Config{
		ConfigEncryptionKey: testEncryptionKey,
		KeyRotationInterval: time.Hour,
	}
	upgraded := bootstrapRegistrySigner(context.Background(), cfg, provider, signer)

	if !upgraded.IsRegistryBacked() {
		t.Fatal("expected registry-backed signer")
	}
	upgraded.StopKeyRefresh()

	if seeded == nil {
		t.Fatal("expected a realm-default key to be seeded")
	}
	if seeded.ClientID != "" || !seeded.Active || seeded.Status != domain.RealmKeyStatusActive ||
		seeded.Name != "realm-default" || seeded.Type != "RSA" || seeded.Priority != 1 {
		t.Fatalf("unexpected seeded key fields: %+v", seeded)
	}
	decrypted, err := pkgcrypto.DecryptAESGCM([]byte(testEncryptionKey), seeded.PrivateKey)
	if err != nil {
		t.Fatalf("failed to decrypt seeded private key: %v", err)
	}
	if decrypted != string(privPEM) {
		t.Fatal("seeded private key does not match the configured key")
	}
}

func TestBootstrapRegistrySigner_NonEmptyRegistry_SkipsSeeding(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	signer, privPEM := newRSASigner(t)
	encPriv, err := pkgcrypto.EncryptAESGCM([]byte(testEncryptionKey), string(privPEM))
	if err != nil {
		t.Fatalf("failed to encrypt private key: %v", err)
	}
	existing := &domain.RealmKey{
		ID:         "realm-default-1",
		Name:       "realm-default",
		Type:       "RSA",
		Active:     true,
		Priority:   1,
		PublicKey:  "test-public-key",
		PrivateKey: encPriv,
		Status:     domain.RealmKeyStatusActive,
	}

	repo := mock_domain.NewMockRealmKeysRepository(ctrl)
	provider := mock_services.NewMockRepositoryProvider(ctrl)
	provider.EXPECT().RealmKeysRepository(gomock.Any()).Return(repo)
	repo.EXPECT().ListAllKeys(gomock.Any()).Return([]*domain.RealmKey{existing}, nil).Times(2)

	cfg := config.Config{
		ConfigEncryptionKey: testEncryptionKey,
		KeyRotationInterval: time.Hour,
	}
	upgraded := bootstrapRegistrySigner(context.Background(), cfg, provider, signer)

	if !upgraded.IsRegistryBacked() {
		t.Fatal("expected registry-backed signer")
	}
	upgraded.StopKeyRefresh()
}
