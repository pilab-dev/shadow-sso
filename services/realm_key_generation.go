package services

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"

	"connectrpc.com/connect"
	"github.com/google/uuid"

	"github.com/pilab-dev/shadow-sso/domain"
	ssov1 "github.com/pilab-dev/shadow-sso/gen/proto/sso/v1"
	"github.com/pilab-dev/shadow-sso/internal/audit"
	pkgcrypto "github.com/pilab-dev/shadow-sso/pkg/crypto"
)

// WithKeyGeneration enables GenerateRealmKey. encryptionKey (32 bytes) seals
// private keys at rest; reload, when set, makes the new key live in the signer.
func (s *RealmServiceServer) WithKeyGeneration(encryptionKey []byte, reload func(context.Context) error) *RealmServiceServer {
	s.encryptionKey = encryptionKey
	s.reloadKeys = reload
	return s
}

// GenerateRealmKey creates, encrypts and stores a new realm-default signing key.
func (s *RealmServiceServer) GenerateRealmKey(ctx context.Context, req *connect.Request[ssov1.GenerateRealmKeyRequest]) (*connect.Response[ssov1.GenerateRealmKeyResponse], error) {
	if len(s.encryptionKey) != 32 {
		return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New("key generation requires a 32 byte config encryption key"))
	}

	privPEM, pubPEM, keyType, err := generateSigningKeyPEM(req.Msg.GetType(), int(req.Msg.GetRsaBits()))
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	sealed, err := pkgcrypto.EncryptAESGCM(s.encryptionKey, privPEM)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to encrypt key"))
	}

	key := &domain.RealmKey{
		ID:         uuid.NewString(),
		Name:       req.Msg.GetName(),
		Type:       keyType,
		Active:     true,
		Priority:   int(req.Msg.GetPriority()),
		PublicKey:  pubPEM,
		PrivateKey: sealed,
		Status:     domain.RealmKeyStatusActive,
	}
	if err := s.keysRepo.SaveRealmKey(ctx, key); err != nil {
		audit.Log("Realm", "RealmKeyGenerated", key.ID, "", "", false, err)
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to save key"))
	}
	if s.reloadKeys != nil {
		if err := s.reloadKeys(ctx); err != nil {
			return nil, connect.NewError(connect.CodeInternal, errors.New("key saved but signer reload failed"))
		}
	}
	audit.Log("Realm", "RealmKeyGenerated", key.ID, "", "", true, nil)

	return connect.NewResponse(&ssov1.GenerateRealmKeyResponse{Key: toRealmKeyProtos([]*domain.RealmKey{key})[0]}), nil
}

// generateSigningKeyPEM returns the private (PKCS#1, SEC1 or PKCS#8) and public
// (PKIX) PEM for a new key, plus the canonical key type the signer understands.
func generateSigningKeyPEM(keyType string, rsaBits int) (priv, pub, canonical string, err error) {
	canonical = strings.ToUpper(strings.TrimSpace(keyType))
	var pubKey any
	var privBlock *pem.Block

	switch canonical {
	case "RSA", "RS256", "RS384", "RS512", "PS256", "PS384", "PS512":
		if rsaBits == 0 {
			rsaBits = 2048
		}
		if rsaBits < 2048 {
			return "", "", "", errors.New("RSA keys must be at least 2048 bits")
		}
		k, e := rsa.GenerateKey(rand.Reader, rsaBits)
		if e != nil {
			return "", "", "", e
		}
		pubKey = &k.PublicKey
		privBlock = &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)}
	case "ES256", "ES384", "ES512":
		curve := map[string]elliptic.Curve{"ES256": elliptic.P256(), "ES384": elliptic.P384(), "ES512": elliptic.P521()}[canonical]
		k, e := ecdsa.GenerateKey(curve, rand.Reader)
		if e != nil {
			return "", "", "", e
		}
		der, e := x509.MarshalECPrivateKey(k)
		if e != nil {
			return "", "", "", e
		}
		pubKey = &k.PublicKey
		privBlock = &pem.Block{Type: "EC PRIVATE KEY", Bytes: der}
	case "EDDSA":
		canonical = "EdDSA"
		pk, k, e := ed25519.GenerateKey(rand.Reader)
		if e != nil {
			return "", "", "", e
		}
		der, e := x509.MarshalPKCS8PrivateKey(k)
		if e != nil {
			return "", "", "", e
		}
		pubKey = pk
		privBlock = &pem.Block{Type: "PRIVATE KEY", Bytes: der}
	default:
		return "", "", "", fmt.Errorf("unsupported key type %q", keyType)
	}

	pubDER, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return "", "", "", err
	}
	return string(pem.EncodeToMemory(privBlock)), string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})), canonical, nil
}
