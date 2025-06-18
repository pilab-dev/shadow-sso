package services

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/pilab-dev/shadow-sso/domain"
	ssov1 "github.com/pilab-dev/shadow-sso/gen/sso/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// --- Mock Implementations ---

type MockSAKeyGenerator struct {
	mock.Mock
}

func (m *MockSAKeyGenerator) GenerateRSAKey() (*rsa.PrivateKey, error) {
	args := m.Called()
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*rsa.PrivateKey), args.Error(1)
}

type MockServiceAccountRepository struct {
	mock.Mock
}

func (m *MockServiceAccountRepository) GetServiceAccount(ctx context.Context, id string) (*domain.ServiceAccount, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.ServiceAccount), args.Error(1)
}
func (m *MockServiceAccountRepository) GetServiceAccountByClientEmail(ctx context.Context, clientEmail string) (*domain.ServiceAccount, error) {
	args := m.Called(ctx, clientEmail)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.ServiceAccount), args.Error(1)
}
func (m *MockServiceAccountRepository) CreateServiceAccount(ctx context.Context, sa *domain.ServiceAccount) error {
	args := m.Called(ctx, sa)
	// Simulate ID generation if repo does it and sa.ID is empty
	if saArg, ok := args.Get(1).(*domain.ServiceAccount); ok {
		if saArg.ID == "" {
			saArg.ID = "mock-sa-id" // Set a mock ID if it's empty
		}
	}
	return args.Error(0)
}
func (m *MockServiceAccountRepository) UpdateServiceAccount(ctx context.Context, sa *domain.ServiceAccount) error {
	args := m.Called(ctx, sa)
	return args.Error(0)
}
func (m *MockServiceAccountRepository) DeleteServiceAccount(ctx context.Context, id string) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

type MockPublicKeyRepository struct {
	mock.Mock
}

func (m *MockPublicKeyRepository) GetPublicKey(ctx context.Context, keyID string) (*domain.PublicKeyInfo, error) {
	args := m.Called(ctx, keyID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.PublicKeyInfo), args.Error(1)
}
func (m *MockPublicKeyRepository) CreatePublicKey(ctx context.Context, pubKeyInfo *domain.PublicKeyInfo) error {
	args := m.Called(ctx, pubKeyInfo)
	// Simulate ID generation if repo does it and pubKeyInfo.ID is empty
	if pkiArg, ok := args.Get(1).(*domain.PublicKeyInfo); ok {
		if pkiArg.ID == "" {
			pkiArg.ID = "mock-key-id" // Set a mock ID
		}
	}
	return args.Error(0)
}
func (m *MockPublicKeyRepository) UpdatePublicKeyStatus(ctx context.Context, keyID string, newStatus string) error {
	args := m.Called(ctx, keyID, newStatus)
	return args.Error(0)
}
func (m *MockPublicKeyRepository) ListPublicKeysForServiceAccount(ctx context.Context, serviceAccountID string, onlyActive bool) ([]*domain.PublicKeyInfo, error) {
	args := m.Called(ctx, serviceAccountID, onlyActive)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*domain.PublicKeyInfo), args.Error(1)
}

// Helper (from service_account_service.go, or make it a public util if used in multiple places)
// func privateKeyToPEMString(privKey *rsa.PrivateKey) string { ... } - Not directly used in mock responses here
func publicKeyToPEMString(pubKey *rsa.PublicKey) (string, error) {
	pubBytes, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes})), nil
}

// --- ServiceAccountServer Tests ---

func TestServiceAccountServer_CreateServiceAccountKey(t *testing.T) {
	ctx := context.Background()
	projectID := "test-project"
	clientEmail := "test-sa@example.com"
	displayName := "Test SA"

	testPrivKey, testPubKey := rsa.GenerateKey(rand.Reader, 512) // Small key for faster test
	testPubKeyPEM, _ := publicKeyToPEMString(testPubKey)

	t.Run("Successful Key Creation - New SA", func(t *testing.T) {
		mockSARepo := new(MockServiceAccountRepository)
		mockPubKeyRepo := new(MockPublicKeyRepository)
		mockKeyGen := new(MockSAKeyGenerator)
		saServer := NewServiceAccountServer(mockKeyGen, mockSARepo, mockPubKeyRepo)

		mockSARepo.On("GetServiceAccountByClientEmail", ctx, clientEmail).Return(nil, errors.New("not found")).Once()
		var createdSA *domain.ServiceAccount
		mockSARepo.On("CreateServiceAccount", ctx, mock.AnythingOfType("*domain.ServiceAccount")).Run(func(args mock.Arguments) {
			saArg := args.Get(1).(*domain.ServiceAccount)
			assert.Equal(t, projectID, saArg.ProjectID)
			assert.Equal(t, clientEmail, saArg.ClientEmail)
			assert.Equal(t, displayName, saArg.DisplayName)
			// Simulate ID assignment by the repo mock or service
			saArg.ID = "new-sa-id-from-mock"
			createdSA = saArg
		}).Return(nil).Once()

		mockKeyGen.On("GenerateRSAKey").Return(testPrivKey, nil).Once()

		var createdPubKeyInfo *domain.PublicKeyInfo
		mockPubKeyRepo.On("CreatePublicKey", ctx, mock.AnythingOfType("*domain.PublicKeyInfo")).Run(func(args mock.Arguments) {
			pkiArg := args.Get(1).(*domain.PublicKeyInfo)
			assert.NotEmpty(t, pkiArg.ID)
			createdPubKeyInfo = pkiArg // Capture for later assertion
			// Ensure createdSA is not nil before accessing its ID
			if createdSA != nil {
				assert.Equal(t, createdSA.ID, pkiArg.ServiceAccountID)
			} else {
				// This case indicates an issue in test setup or Run func sequencing if createdSA is nil here
				assert.Fail(t, "createdSA was nil when CreatePublicKey Run func executed")
			}
			assert.Equal(t, testPubKeyPEM, pkiArg.PublicKey)
			assert.Equal(t, "RS256", pkiArg.Algorithm)
			assert.Equal(t, "ACTIVE", pkiArg.Status)
		}).Return(nil).Once()

		req := connect.NewRequest(&ssov1.CreateServiceAccountKeyRequest{
			ProjectId: projectID, ClientEmail: clientEmail, DisplayName: displayName,
		})
		resp, err := saServer.CreateServiceAccountKey(ctx, req)

		require.NoError(t, err)
		require.NotNil(t, resp); require.NotNil(t, resp.Msg); require.NotNil(t, resp.Msg.Key)
		assert.Equal(t, projectID, resp.Msg.Key.ProjectId)
		assert.Equal(t, clientEmail, resp.Msg.Key.ClientEmail)
		require.NotNil(t, createdPubKeyInfo, "createdPubKeyInfo should have been captured")
		assert.Equal(t, createdPubKeyInfo.ID, resp.Msg.Key.PrivateKeyId)
		assert.Contains(t, resp.Msg.Key.PrivateKey, "RSA PRIVATE KEY")
		require.NotNil(t, createdSA, "createdSA should have been captured")
		assert.Equal(t, createdSA.ID, resp.Msg.ServiceAccountId)

		mockSARepo.AssertExpectations(t)
		mockPubKeyRepo.AssertExpectations(t)
		mockKeyGen.AssertExpectations(t)
	})

	t.Run("Successful Key Creation - Existing SA", func(t *testing.T) {
		mockSARepo := new(MockServiceAccountRepository)
		mockPubKeyRepo := new(MockPublicKeyRepository)
		mockKeyGen := new(MockSAKeyGenerator)
		saServer := NewServiceAccountServer(mockKeyGen, mockSARepo, mockPubKeyRepo)

		existingSA := &domain.ServiceAccount{ID: "existing-sa-id", ProjectID: projectID, ClientEmail: clientEmail, Disabled: false}
		mockSARepo.On("GetServiceAccountByClientEmail", ctx, clientEmail).Return(existingSA, nil).Once()
		mockKeyGen.On("GenerateRSAKey").Return(testPrivKey, nil).Once()
		mockPubKeyRepo.On("CreatePublicKey", ctx, mock.MatchedBy(func(pki *domain.PublicKeyInfo) bool {
			return pki.ServiceAccountID == existingSA.ID
		})).Return(nil).Once()

		req := connect.NewRequest(&ssov1.CreateServiceAccountKeyRequest{
			ProjectId: projectID, ClientEmail: clientEmail, DisplayName: displayName,
		})
		resp, err := saServer.CreateServiceAccountKey(ctx, req)
		require.NoError(t, err)
		assert.Equal(t, existingSA.ID, resp.Msg.ServiceAccountId)
		mockSARepo.AssertExpectations(t)
		mockKeyGen.AssertExpectations(t)
		mockPubKeyRepo.AssertExpectations(t)
		mockSARepo.AssertNotCalled(t, "CreateServiceAccount", mock.Anything, mock.Anything)
	})

	t.Run("Key Creation - RSA Generation Fails", func(t *testing.T) {
		mockSARepo := new(MockServiceAccountRepository)
		mockPubKeyRepo := new(MockPublicKeyRepository) // Not called
		mockKeyGen := new(MockSAKeyGenerator)
		saServer := NewServiceAccountServer(mockKeyGen, mockSARepo, mockPubKeyRepo)

		mockSARepo.On("GetServiceAccountByClientEmail", ctx, clientEmail).Return(nil, errors.New("not found")).Once()
		mockSARepo.On("CreateServiceAccount", ctx, mock.AnythingOfType("*domain.ServiceAccount")).Return(nil).Once()
		mockKeyGen.On("GenerateRSAKey").Return(nil, errors.New("rsa error")).Once()

		req := connect.NewRequest(&ssov1.CreateServiceAccountKeyRequest{ProjectId: projectID, ClientEmail: clientEmail})
		_, err := saServer.CreateServiceAccountKey(ctx, req)
		require.Error(t, err)
		connectErr, ok := err.(*connect.Error)
		require.True(t, ok)
		assert.Equal(t, connect.CodeInternal, connectErr.Code())
		assert.Contains(t, connectErr.Message(), "generate RSA key")
		mockSARepo.AssertExpectations(t)
		mockKeyGen.AssertExpectations(t)
		mockPubKeyRepo.AssertNotCalled(t, "CreatePublicKey", mock.Anything, mock.Anything)
	})
}

func TestServiceAccountServer_ListServiceAccountKeys(t *testing.T) {
	mockSARepo := new(MockServiceAccountRepository)
	mockPubKeyRepo := new(MockPublicKeyRepository)
	mockKeyGen := new(MockSAKeyGenerator)
	saServer := NewServiceAccountServer(mockKeyGen, mockSARepo, mockPubKeyRepo)
	ctx := context.Background()
	serviceAccountID := "sa-id-for-list"

	// Reset mocks for this test function
	defer func() {
		mockSARepo.ExpectedCalls = nil; mockSARepo.Calls = nil
		mockPubKeyRepo.ExpectedCalls = nil; mockPubKeyRepo.Calls = nil
		mockKeyGen.ExpectedCalls = nil; mockKeyGen.Calls = nil
	}()


	t.Run("Successful List Keys", func(t *testing.T) {
		now := time.Now()
		dbKeys := []*domain.PublicKeyInfo{
			{ID: "key1", ServiceAccountID: serviceAccountID, Algorithm: "RS256", Status: "ACTIVE", CreatedAt: now.Unix(), ExpiresAt: timestamppb.New(now.Add(time.Hour)).Seconds},
		}
		mockPubKeyRepo.On("ListPublicKeysForServiceAccount", ctx, serviceAccountID, true).Return(dbKeys, nil).Once()

		req := connect.NewRequest(&ssov1.ListServiceAccountKeysRequest{ServiceAccountId: serviceAccountID})
		resp, err := saServer.ListServiceAccountKeys(ctx, req)

		require.NoError(t, err)
		require.NotNil(t, resp); require.NotNil(t, resp.Msg)
		assert.Len(t, resp.Msg.Keys, 1)
		if len(resp.Msg.Keys) == 1 {
			assert.Equal(t, dbKeys[0].ID, resp.Msg.Keys[0].KeyId)
			assert.Equal(t, "ACTIVE", resp.Msg.Keys[0].Status)
			assert.Equal(t, dbKeys[0].CreatedAt, resp.Msg.Keys[0].CreatedAt.Seconds)
		}
		mockPubKeyRepo.AssertExpectations(t)
	})
}

func TestServiceAccountServer_DeleteServiceAccountKey(t *testing.T) {
	mockSARepo := new(MockServiceAccountRepository)
	mockPubKeyRepo := new(MockPublicKeyRepository)
	mockKeyGen := new(MockSAKeyGenerator)
	saServer := NewServiceAccountServer(mockKeyGen, mockSARepo, mockPubKeyRepo)
	ctx := context.Background()
	serviceAccountID := "sa-id-for-delete"
	keyIDToDelete := "key-to-delete"

	defer func() { // Reset mocks
		mockSARepo.ExpectedCalls = nil; mockSARepo.Calls = nil
		mockPubKeyRepo.ExpectedCalls = nil; mockPubKeyRepo.Calls = nil
		mockKeyGen.ExpectedCalls = nil; mockKeyGen.Calls = nil
	}()


	t.Run("Successful Delete Key", func(t *testing.T) {
		mockPubKeyRepo.On("UpdatePublicKeyStatus", ctx, keyIDToDelete, "REVOKED").Return(nil).Once()

		req := connect.NewRequest(&ssov1.DeleteServiceAccountKeyRequest{ServiceAccountId: serviceAccountID, KeyId: keyIDToDelete})
		_, err := saServer.DeleteServiceAccountKey(ctx, req)

		require.NoError(t, err)
		mockPubKeyRepo.AssertExpectations(t)
	})
}
