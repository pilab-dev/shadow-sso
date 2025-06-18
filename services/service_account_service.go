package services

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt" // For error formatting

	"connectrpc.com/connect"
	"github.com/google/uuid" // For generating key IDs
	"github.com/pilab-dev/shadow-sso/domain"
	ssov1 "github.com/pilab-dev/shadow-sso/gen/sso/v1"
	"github.com/pilab-dev/shadow-sso/gen/sso/v1/ssov1connect"
	"google.golang.org/protobuf/types/known/emptypb"
	// Add other necessary imports like service_account_repository, public_key_repository
)

// SAKeyGenerator defines an interface for generating RSA keys, to allow for mocking.
type SAKeyGenerator interface {
	GenerateRSAKey() (*rsa.PrivateKey, error)
}

// DefaultSAKeyGenerator uses crypto/rand to generate RSA keys.
type DefaultSAKeyGenerator struct{}

func (g *DefaultSAKeyGenerator) GenerateRSAKey() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, 2048)
}


// ServiceAccountServer implements the ssov1connect.ServiceAccountServiceHandler interface.
type ServiceAccountServer struct {
	ssov1connect.UnimplementedServiceAccountServiceHandler // Embed for forward compatibility
	saRepo         domain.ServiceAccountRepository
	pubKeyRepo     domain.PublicKeyRepository
	KeyGenerator   SAKeyGenerator
}

// NewServiceAccountServer creates a new ServiceAccountServer.
func NewServiceAccountServer(
	keyGen SAKeyGenerator,
	saRepo domain.ServiceAccountRepository,
	pubKeyRepo domain.PublicKeyRepository,
) *ServiceAccountServer {
	return &ServiceAccountServer{
		KeyGenerator: keyGen,
		saRepo:       saRepo,
		pubKeyRepo:   pubKeyRepo,
	}
}

func (s *ServiceAccountServer) CreateServiceAccountKey(ctx context.Context, req *connect.Request[ssov1.CreateServiceAccountKeyRequest]) (*connect.Response[ssov1.CreateServiceAccountKeyResponse], error) {
	// 1. Validate input: req.GetProjectId()
	// 2. Find or Create ServiceAccount in saRepo:
	//    - If client_email is provided, try to find by that.
	//    - Otherwise, generate a client_email (e.g., sa-<uuid>@<project_id>.iam.sso.dev)
	//    - Store/update ServiceAccount (domain.ServiceAccount)
	// 3. Generate RSA private key using s.KeyGenerator.GenerateRSAKey()
	// 4. Generate PrivateKeyID (e.g., hex of SHA256 of public key bytes or simple UUID)
	// 5. Store Public Key Info (domain.PublicKeyInfo) in pubKeyRepo:
	//    - PEM encode public key
	//    - Store PrivateKeyID, ServiceAccountID, PublicKey (PEM), Algorithm ("RS256"), Status ("ACTIVE")
	// 6. Format private key into JSON structure (ssov1.ServiceAccountKey):
	//    - Type: "service_account"
	//    - ProjectID: from request or SA
	//    - PrivateKeyID: generated
	//    - PrivateKey: PEM encode private key
	//    - ClientEmail: from SA
	//    - ClientID: from SA (if applicable)
	//    - AuthURI: "https://sso.example.com/auth" (config)
	//    - TokenURI: "https://sso.example.com/token" (config)
	//    - AuthProviderX509CertURL: "https://sso.example.com/certs" (config)
	//    - ClientX509CertURL: "https://sso.example.com/certs/<client_id>" (config, hypothetical)
	// 7. Return CreateServiceAccountKeyResponse

	privateKeyID := uuid.New().String()
	saID := uuid.New().String() // Placeholder for actual service account ID

	// Example of using the KeyGenerator
	_, err := s.KeyGenerator.GenerateRSAKey()
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to generate RSA key: %w", err))
	}
	// ... rest of the logic for PEM encoding, etc.

	return nil, connect.NewError(connect.CodeUnimplemented, "CreateServiceAccountKey not implemented")
}

func (s *ServiceAccountServer) ListServiceAccountKeys(ctx context.Context, req *connect.Request[ssov1.ListServiceAccountKeysRequest]) (*connect.Response[ssov1.ListServiceAccountKeysResponse], error) {
	// 1. Validate req.GetServiceAccountId()
	// 2. Fetch active public keys (domain.PublicKeyInfo) for the service_account_id from pubKeyRepo
	// 3. Convert to ssov1.StoredServiceAccountKeyInfo
	return nil, connect.NewError(connect.CodeUnimplemented, "ListServiceAccountKeys not implemented")
}

func (s *ServiceAccountServer) DeleteServiceAccountKey(ctx context.Context, req *connect.Request[ssov1.DeleteServiceAccountKeyRequest]) (*connect.Response[emptypb.Empty], error) {
	// 1. Validate req.GetServiceAccountId() and req.GetKeyId()
	// 2. Update key status to "REVOKED" or delete from pubKeyRepo
	//    (Consider if actual deletion or just marking as revoked is better for audit)
	return nil, connect.NewError(connect.CodeUnimplemented, "DeleteServiceAccountKey not implemented")
}

// Helper function (can be moved to a util package)
func privateKeyToPEM(privKey *rsa.PrivateKey) []byte {
	return pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(privKey),
		},
	)
}

func publicKeyToPEM(pubKey *rsa.PublicKey) ([]byte, error) {
	pubBytes, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(
		&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: pubBytes,
		},
	), nil
}
// Ensure ServiceAccountServer implements ssov1connect.ServiceAccountServiceHandler
var _ ssov1connect.ServiceAccountServiceHandler = (*ServiceAccountServer)(nil)
