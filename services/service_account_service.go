package services

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt" // For error formatting
	"time"

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
	saRepo                                                 domain.ServiceAccountRepository
	pubKeyRepo                                             domain.PublicKeyRepository
	KeyGenerator                                           SAKeyGenerator
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
	projectID := req.Msg.GetProjectId()
	clientEmail := req.Msg.GetClientEmail()
	displayName := req.Msg.GetDisplayName()

	if projectID == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("project_id is required"))
	}
	if clientEmail == "" {
		// Generate client email if not provided
		uid := uuid.New().String()
		clientEmail = fmt.Sprintf("sa-%s@%s.iam.sso.dev", uid[:8], projectID)
	}

	// Try to find existing service account
	var serviceAccount *domain.ServiceAccount
	sa, err := s.saRepo.GetServiceAccountByClientEmail(ctx, clientEmail)
	if err != nil {
		// Create new service account if not found
		now := time.Now().Unix()
		serviceAccount = &domain.ServiceAccount{
			ProjectID:   projectID,
			ClientEmail: clientEmail,
			DisplayName: displayName,
			Disabled:    false,
			CreatedAt:   now,
			UpdatedAt:   now,
		}
		if err := s.saRepo.CreateServiceAccount(ctx, serviceAccount); err != nil {
			return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to create service account: %w", err))
		}
	} else {
		serviceAccount = sa
	}

	// Generate RSA key
	privateKey, err := s.KeyGenerator.GenerateRSAKey()
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to generate RSA key: %w", err))
	}

	// Generate Private Key ID and prepare Public Key Info
	privateKeyID := uuid.New().String()
	pubKeyPEM, err := publicKeyToPEM(&privateKey.PublicKey)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to PEM encode public key: %w", err))
	}

	// Store Public Key Info
	pubKeyInfo := &domain.PublicKeyInfo{
		ID:               privateKeyID,
		ServiceAccountID: serviceAccount.ID,
		PublicKey:        string(pubKeyPEM),
		Algorithm:        "RS256",
		Status:           "ACTIVE",
		CreatedAt:        time.Now().Unix(),
	}
	if err := s.pubKeyRepo.CreatePublicKey(ctx, pubKeyInfo); err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to store public key: %w", err))
	}

	// Format private key into JSON response
	saKey := &ssov1.ServiceAccountKey{
		Type:                    "service_account",
		ProjectId:               serviceAccount.ProjectID,
		PrivateKeyId:            privateKeyID,
		PrivateKey:              string(privateKeyToPEM(privateKey)),
		ClientEmail:             serviceAccount.ClientEmail,
		ClientId:                serviceAccount.ClientID,
		AuthUri:                 "https://sso.pilab.hu/auth",                                            // TODO: Get from config
		TokenUri:                "https://sso.pilab.hu/token",                                           // TODO: Get from config
		AuthProviderX509CertUrl: "https://sso.pilab.hu/certs",                                           // TODO: Get from config
		ClientX509CertUrl:       fmt.Sprintf("https://sso..pilab.hu/certs/%s", serviceAccount.ClientID), // TODO: Get from config
	}

	return connect.NewResponse(&ssov1.CreateServiceAccountKeyResponse{
		ServiceAccountId: serviceAccount.ID,
		Key:              saKey,
	}), nil
}

func (s *ServiceAccountServer) ListServiceAccountKeys(ctx context.Context, req *connect.Request[ssov1.ListServiceAccountKeysRequest]) (*connect.Response[ssov1.ListServiceAccountKeysResponse], error) {
	// 1. Validate req.GetServiceAccountId()
	// 2. Fetch active public keys (domain.PublicKeyInfo) for the service_account_id from pubKeyRepo
	// 3. Convert to ssov1.StoredServiceAccountKeyInfo
	return nil, connect.NewError(connect.CodeUnimplemented, errors.New("ListServiceAccountKeys not implemented"))
}

func (s *ServiceAccountServer) DeleteServiceAccountKey(ctx context.Context, req *connect.Request[ssov1.DeleteServiceAccountKeyRequest]) (*connect.Response[emptypb.Empty], error) {
	// 1. Validate req.GetServiceAccountId() and req.GetKeyId()
	// 2. Update key status to "REVOKED" or delete from pubKeyRepo
	//    (Consider if actual deletion or just marking as revoked is better for audit)
	return nil, connect.NewError(connect.CodeUnimplemented, errors.New("DeleteServiceAccountKey not implemented"))
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
