package services

import (
	"context"
	"errors"
	// "fmt" // Not directly used yet, but common
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/pilab-dev/shadow-sso/client" // For client.Client, client.Confidential, client.Public
	// "github.com/pilab-dev/shadow-sso/domain" // Not directly used here, but good to have for context
	ssov1 "github.com/pilab-dev/shadow-sso/gen/sso/v1"
	// "github.com/pilab-dev/shadow-sso/internal/auth/rbac" // For permissions, if checking them directly
	"github.com/pilab-dev/shadow-sso/ssso" // For ssso.OAuthRepository interface
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	// "google.golang.org/protobuf/types/known/timestamppb"
)

// --- Mock Implementations ---

type MockOAuthRepository struct {
	mock.Mock
}

func (m *MockOAuthRepository) CreateClient(ctx context.Context, c *client.Client) error {
	args := m.Called(ctx, c)
	return args.Error(0)
}
func (m *MockOAuthRepository) GetClient(ctx context.Context, clientID string) (*client.Client, error) {
	args := m.Called(ctx, clientID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*client.Client), args.Error(1)
}
func (m *MockOAuthRepository) ListClients(ctx context.Context, pageSize int32, pageToken string) ([]*client.Client, string, error) {
	args := m.Called(ctx, pageSize, pageToken)
	if args.Get(0) == nil {
		return nil, args.String(1), args.Error(2)
	}
	return args.Get(0).([]*client.Client), args.String(1), args.Error(2)
}
func (m *MockOAuthRepository) UpdateClient(ctx context.Context, c *client.Client) error {
	args := m.Called(ctx, c)
	return args.Error(0)
}
func (m *MockOAuthRepository) DeleteClient(ctx context.Context, clientID string) error {
	args := m.Called(ctx, clientID)
	return args.Error(0)
}

// Mock other ssso.OAuthRepository methods to satisfy the interface if it's broad
func (m *MockOAuthRepository) StoreToken(ctx context.Context, token *ssso.Token) error {
	args := m.Called(ctx, token); return args.Error(0)
}
func (m *MockOAuthRepository) GetAccessToken(ctx context.Context, tokenValue string) (*ssso.Token, error) {
	args := m.Called(ctx, tokenValue); if args.Get(0) == nil { return nil, args.Error(1) }; return args.Get(0).(*ssso.Token), args.Error(1)
}
func (m *MockOAuthRepository) RevokeToken(ctx context.Context, tokenValue string) error {
	args := m.Called(ctx, tokenValue); return args.Error(0)
}
func (m *MockOAuthRepository) GetRefreshTokenInfo(ctx context.Context, tokenValue string) (*ssso.TokenInfo, error) {
	args := m.Called(ctx, tokenValue); if args.Get(0) == nil { return nil, args.Error(1) }; return args.Get(0).(*ssso.TokenInfo), args.Error(1)
}
func (m *MockOAuthRepository) GetAccessTokenInfo(ctx context.Context, tokenValue string) (*ssso.TokenInfo, error) {
	args := m.Called(ctx, tokenValue); if args.Get(0) == nil { return nil, args.Error(1) }; return args.Get(0).(*ssso.TokenInfo), args.Error(1)
}
func (m *MockOAuthRepository) ValidateClient(ctx context.Context, clientID, clientSecret string) error {
	args := m.Called(ctx, clientID, clientSecret); return args.Error(0)
}
func (m *MockOAuthRepository) Close() error { args := m.Called(); return args.Error(0)}
func (m *MockOAuthRepository) SaveAuthCode(ctx context.Context, code *ssso.AuthCode) error { args := m.Called(ctx,code); return args.Error(0)}
func (m *MockOAuthRepository) GetAuthCode(ctx context.Context, code string) (*ssso.AuthCode, error) { args := m.Called(ctx,code); if args.Get(0) == nil { return nil, args.Error(1)}; return args.Get(0).(*ssso.AuthCode), args.Error(1)}
func (m *MockOAuthRepository) MarkAuthCodeAsUsed(ctx context.Context, code string) error { args := m.Called(ctx,code); return args.Error(0)}
func (m *MockOAuthRepository) DeleteExpiredAuthCodes(ctx context.Context) error { args := m.Called(ctx); return args.Error(0)}
func (m *MockOAuthRepository) GetRefreshToken(ctx context.Context, tokenValue string) (*ssso.Token, error) { args := m.Called(ctx, tokenValue); if args.Get(0) == nil { return nil, args.Error(1)}; return args.Get(0).(*ssso.Token), args.Error(1)}
func (m *MockOAuthRepository) RevokeRefreshToken(ctx context.Context, tokenValue string) error { args := m.Called(ctx, tokenValue); return args.Error(0)}
func (m *MockOAuthRepository) RevokeAllUserTokens(ctx context.Context, userID string) error { args := m.Called(ctx, userID); return args.Error(0)}
func (m *MockOAuthRepository) RevokeAllClientTokens(ctx context.Context, clientID string) error { args := m.Called(ctx, clientID); return args.Error(0)}
func (m *MockOAuthRepository) DeleteExpiredTokens(ctx context.Context) error { args := m.Called(ctx); return args.Error(0)}
func (m *MockOAuthRepository) ValidateAccessToken(ctx context.Context, token string) (string, error) { args := m.Called(ctx,token); return args.String(0), args.Error(1)}
func (m *MockOAuthRepository) GetTokenInfo(ctx context.Context, tokenValue string) (*ssso.Token, error) { args := m.Called(ctx, tokenValue); if args.Get(0) == nil { return nil, args.Error(1)}; return args.Get(0).(*ssso.Token), args.Error(1)}
func (m *MockOAuthRepository) SaveCodeChallenge(ctx context.Context, code, challenge string) error { args := m.Called(ctx,code,challenge); return args.Error(0)}
func (m *MockOAuthRepository) GetCodeChallenge(ctx context.Context, code string) (string, error) { args := m.Called(ctx,code); return args.String(0), args.Error(1)}
func (m *MockOAuthRepository) DeleteCodeChallenge(ctx context.Context, code string) error { args := m.Called(ctx,code); return args.Error(0)}


// Re-define MockPasswordHasher if not in a shared test util package
type MockPasswordHasher struct {
	mock.Mock
}

func (m *MockPasswordHasher) Hash(password string) (string, error) {
	args := m.Called(password)
	return args.String(0), args.Error(1)
}
func (m *MockPasswordHasher) Verify(hashedPassword, password string) error {
	args := m.Called(hashedPassword, password)
	return args.Error(0)
}

// --- ClientManagementServer Tests ---

func TestClientManagementServer_RegisterClient(t *testing.T) {
	mockOAuthRepo := new(MockOAuthRepository)
	mockHasher := new(MockPasswordHasher)
	service := NewClientManagementServer(mockOAuthRepo, mockHasher)
	ctx := context.Background()

	reqMsgConfidential := &ssov1.RegisterClientRequest{
		ClientName:    "Test Confidential Client",
		ClientType:    ssov1.ClientTypeProto_CLIENT_TYPE_CONFIDENTIAL,
		RedirectUris:  []string{"http://localhost/callback"},
		AllowedScopes: []string{"openid", "profile"},
	}
	hashedSecret := "hashed_super_secret_string_longer_than_uuid"

	t.Run("Successful Confidential Client Registration", func(t *testing.T) {
		// Reset mocks for sub-test
		mockOAuthRepo := new(MockOAuthRepository)
		mockHasher := new(MockPasswordHasher)
		serviceSub := NewClientManagementServer(mockOAuthRepo, mockHasher)

		mockHasher.On("Hash", mock.AnythingOfType("string")).Return(hashedSecret, nil).Once()
		var capturedClient *client.Client
		mockOAuthRepo.On("CreateClient", ctx, mock.AnythingOfType("*client.Client")).Run(func(args mock.Arguments) {
			capturedClient = args.Get(1).(*client.Client)
			assert.Equal(t, reqMsgConfidential.ClientName, capturedClient.Name)
			assert.Equal(t, client.Confidential, capturedClient.Type)
			assert.Equal(t, hashedSecret, capturedClient.Secret)
			assert.True(t, capturedClient.IsActive)
		}).Return(nil).Once()

		resp, err := serviceSub.RegisterClient(ctx, connect.NewRequest(reqMsgConfidential))

		require.NoError(t, err)
		require.NotNil(t, resp); require.NotNil(t, resp.Msg); require.NotNil(t, resp.Msg.Client)
		assert.NotEmpty(t, resp.Msg.Client.ClientId)
		assert.Equal(t, reqMsgConfidential.ClientName, resp.Msg.Client.ClientName)
		assert.Equal(t, ssov1.ClientTypeProto_CLIENT_TYPE_CONFIDENTIAL, resp.Msg.Client.ClientType)
		assert.NotEmpty(t, resp.Msg.Client.ClientSecret, "Plaintext secret should be in response for confidential client")
		assert.NotEqual(t, hashedSecret, resp.Msg.Client.ClientSecret, "Response secret should be plaintext, not hashed")

		mockOAuthRepo.AssertExpectations(t)
		mockHasher.AssertExpectations(t)
	})

	t.Run("Successful Public Client Registration", func(t *testing.T) {
		mockOAuthRepo := new(MockOAuthRepository)
		mockHasher := new(MockPasswordHasher) // Should not be called
		serviceSub := NewClientManagementServer(mockOAuthRepo, mockHasher)

		publicReqMsg := &ssov1.RegisterClientRequest{
			ClientName: "Test Public Client", ClientType: ssov1.ClientTypeProto_CLIENT_TYPE_PUBLIC,
			RedirectUris: []string{"com.myapp://callback"},
		}
		var capturedClient *client.Client
		mockOAuthRepo.On("CreateClient", ctx, mock.AnythingOfType("*client.Client")).Run(func(args mock.Arguments) {
			capturedClient = args.Get(1).(*client.Client)
			assert.Equal(t, client.Public, capturedClient.Type)
			assert.Empty(t, capturedClient.Secret)
			assert.True(t, capturedClient.RequirePKCE)
		}).Return(nil).Once()

		resp, err := serviceSub.RegisterClient(ctx, connect.NewRequest(publicReqMsg))
		require.NoError(t, err)
		require.NotNil(t, resp.Msg.Client)
		assert.Empty(t, resp.Msg.Client.ClientSecret)
		assert.Equal(t, ssov1.ClientTypeProto_CLIENT_TYPE_PUBLIC, resp.Msg.Client.ClientType)

		mockOAuthRepo.AssertExpectations(t)
		mockHasher.AssertNotCalled(t, "Hash", mock.Anything)
	})

	t.Run("Registration Fails - Hash Error", func(t *testing.T) {
		mockOAuthRepo := new(MockOAuthRepository) // Not called
		mockHasher := new(MockPasswordHasher)
		serviceSub := NewClientManagementServer(mockOAuthRepo, mockHasher)

		mockHasher.On("Hash", mock.AnythingOfType("string")).Return("", errors.New("hash failed")).Once()

		_, err := serviceSub.RegisterClient(ctx, connect.NewRequest(reqMsgConfidential)) // Use confidential client req
		require.Error(t, err)
		connectErr, ok := err.(*connect.Error)
		require.True(t, ok)
		assert.Equal(t, connect.CodeInternal, connectErr.Code())
		mockHasher.AssertExpectations(t)
		mockOAuthRepo.AssertNotCalled(t, "CreateClient", mock.Anything, mock.Anything)
	})

	t.Run("Registration Fails - Repo CreateClient Error", func(t *testing.T) {
		mockOAuthRepo := new(MockOAuthRepository)
		mockHasher := new(MockPasswordHasher)
		serviceSub := NewClientManagementServer(mockOAuthRepo, mockHasher)

		mockHasher.On("Hash", mock.AnythingOfType("string")).Return(hashedSecret, nil).Once()
		mockOAuthRepo.On("CreateClient", ctx, mock.AnythingOfType("*client.Client")).Return(errors.New("db error")).Once()

		_, err := serviceSub.RegisterClient(ctx, connect.NewRequest(reqMsgConfidential))
		require.Error(t, err)
		connectErr, ok := err.(*connect.Error)
		require.True(t, ok)
		assert.Equal(t, connect.CodeInternal, connectErr.Code())
		mockHasher.AssertExpectations(t)
		mockOAuthRepo.AssertExpectations(t)
	})
}

func TestClientManagementServer_GetClient(t *testing.T) {
	mockOAuthRepo := new(MockOAuthRepository)
	service := NewClientManagementServer(mockOAuthRepo, nil) // Hasher not used in Get
	ctx := context.Background()
	clientID := "test-client-id"
	dbClient := &client.Client{ // Using client.Client from the correct package
		ID: clientID, Name: "Fetched Client", Type: client.Confidential, IsActive: true,
		Secret: "hashed_secret_in_db",
		CreatedAt: time.Now().Add(-time.Hour), UpdatedAt: time.Now(),
	}

	t.Run("Successful GetClient", func(t *testing.T) {
		mockOAuthRepo.On("GetClient", ctx, clientID).Return(dbClient, nil).Once()
		req := connect.NewRequest(&ssov1.GetClientRequest{ClientId: clientID})
		resp, err := service.GetClient(ctx, req)

		require.NoError(t, err)
		require.NotNil(t, resp); require.NotNil(t, resp.Msg); require.NotNil(t, resp.Msg.Client)
		assert.Equal(t, clientID, resp.Msg.Client.ClientId)
		assert.Equal(t, dbClient.Name, resp.Msg.Client.ClientName)
		assert.Empty(t, resp.Msg.Client.ClientSecret, "Secret should be omitted in GetClient response")
		assert.Equal(t, ssov1.ClientTypeProto_CLIENT_TYPE_CONFIDENTIAL, resp.Msg.Client.ClientType)
		mockOAuthRepo.AssertExpectations(t)
	})

	t.Run("GetClient_NotFound", func(t *testing.T) {
		mockOAuthRepo.On("GetClient", ctx, clientID).Return(nil, errors.New("client not found")).Once()
		req := connect.NewRequest(&ssov1.GetClientRequest{ClientId: clientID})
		_, err := service.GetClient(ctx, req)

		require.Error(t, err)
		connectErr, ok := err.(*connect.Error)
		require.True(t, ok)
		assert.Equal(t, connect.CodeNotFound, connectErr.Code())
		mockOAuthRepo.AssertExpectations(t)
	})
}

// TODO: Add tests for ListClients (mocking repo ListClients, checking pagination, ensuring secrets omitted)
// TODO: Add tests for UpdateClient (success, not found, handling of partial updates/fields, secret not changed/exposed)
// TODO: Add tests for DeleteClient (success, not found)

func TestClientManagementServer_ListClients(t *testing.T) {
	mockOAuthRepo := new(MockOAuthRepository)
	service := NewClientManagementServer(mockOAuthRepo, nil) // Hasher not used in List
	ctx := context.Background()

	dbClients := []*client.Client{
		{ID: "client1", Name: "Client Alpha", Type: client.Public, IsActive: true, CreatedAt: time.Now()},
		{ID: "client2", Name: "Client Beta", Type: client.Confidential, IsActive: true, CreatedAt: time.Now(), Secret: "hashed_secret_beta"},
	}
	nextPageToken := "nextpage"

	t.Run("Successful ListClients", func(t *testing.T) {
		// Reset mock for sub-test
		mockOAuthRepo := new(MockOAuthRepository)
		service := NewClientManagementServer(mockOAuthRepo, nil)

		mockOAuthRepo.On("ListClients", ctx, int32(10), "").Return(dbClients, nextPageToken, nil).Once()

		req := connect.NewRequest(&ssov1.ListClientsRequest{PageSize: 10, PageToken: ""})
		resp, err := service.ListClients(ctx, req)

		require.NoError(t, err)
		require.NotNil(t, resp); require.NotNil(t, resp.Msg)
		assert.Len(t, resp.Msg.Clients, 2)
		assert.Equal(t, nextPageToken, resp.Msg.NextPageToken)
		if len(resp.Msg.Clients) > 0 {
			assert.Equal(t, dbClients[0].Name, resp.Msg.Clients[0].ClientName)
			assert.Empty(t, resp.Msg.Clients[1].ClientSecret, "Secret should be omitted in list response")
		}
		mockOAuthRepo.AssertExpectations(t)
	})

	t.Run("ListClients_RepoError", func(t *testing.T) {
		mockOAuthRepo := new(MockOAuthRepository)
		service := NewClientManagementServer(mockOAuthRepo, nil)
		mockOAuthRepo.On("ListClients", ctx, int32(10), "").Return(nil, "", errors.New("db error")).Once()

		req := connect.NewRequest(&ssov1.ListClientsRequest{PageSize: 10, PageToken: ""})
		resp, err := service.ListClients(ctx, req)

		require.Error(t, err)
		assert.Nil(t, resp)
		connectErr, ok := err.(*connect.Error)
		require.True(t, ok)
		assert.Equal(t, connect.CodeInternal, connectErr.Code())
		mockOAuthRepo.AssertExpectations(t)
	})
}

func TestClientManagementServer_UpdateClient(t *testing.T) {
	mockOAuthRepo := new(MockOAuthRepository)
	mockHasher := new(MockPasswordHasher)
	service := NewClientManagementServer(mockOAuthRepo, mockHasher)
	ctx := context.Background()
	clientID := "client-to-update"
	originalClient := &client.Client{
		ID: clientID, Name: "Original Name", Type: client.Confidential, IsActive: true,
		RedirectURIs: []string{"http://old.com/cb"}, CreatedAt: time.Now().Add(-time.Hour), Secret: "hashed_secret",
		UpdatedAt: time.Now().Add(-time.Minute),
	}

	t.Run("Successful UpdateClient", func(t *testing.T) {
		mockOAuthRepo := new(MockOAuthRepository)
		service := NewClientManagementServer(mockOAuthRepo, mockHasher)

		mockOAuthRepo.On("GetClient", ctx, clientID).Return(originalClient, nil).Once()

		var updatedClientArg *client.Client
		mockOAuthRepo.On("UpdateClient", ctx, mock.AnythingOfType("*client.Client")).Run(func(args mock.Arguments) {
			updatedClientArg = args.Get(1).(*client.Client)
			assert.Equal(t, "New Updated Name", updatedClientArg.Name)
			assert.Equal(t, []string{"http://new.com/cb"}, updatedClientArg.RedirectURIs)
			assert.False(t, updatedClientArg.IsActive) // Check IsActive update
			assert.True(t, updatedClientArg.UpdatedAt.After(originalClient.UpdatedAt))
		}).Return(nil).Once()

		req := connect.NewRequest(&ssov1.UpdateClientRequest{
			ClientId:     clientID,
			ClientName:   "New Updated Name",
			RedirectUris: []string{"http://new.com/cb"},
			IsActive:     false, // Test deactivating
		})
		resp, err := service.UpdateClient(ctx, req)

		require.NoError(t, err)
		require.NotNil(t, resp); require.NotNil(t, resp.Msg); require.NotNil(t, resp.Msg.Client)
		assert.Equal(t, "New Updated Name", resp.Msg.Client.ClientName)
		assert.False(t, resp.Msg.Client.IsActive)
		assert.Empty(t, resp.Msg.Client.ClientSecret)
		mockOAuthRepo.AssertExpectations(t)
	})

	t.Run("UpdateClient_NotFound", func(t *testing.T) {
		mockOAuthRepo := new(MockOAuthRepository)
		service := NewClientManagementServer(mockOAuthRepo, mockHasher)
		mockOAuthRepo.On("GetClient", ctx, clientID).Return(nil, errors.New("client not found")).Once()

		req := connect.NewRequest(&ssov1.UpdateClientRequest{ClientId: clientID, ClientName: "name"})
		_, err := service.UpdateClient(ctx, req)
		require.Error(t, err)
		connectErr, ok := err.(*connect.Error)
		require.True(t, ok)
		assert.Equal(t, connect.CodeNotFound, connectErr.Code())
		mockOAuthRepo.AssertExpectations(t)
		mockOAuthRepo.AssertNotCalled(t, "UpdateClient", mock.Anything, mock.Anything)
	})

	t.Run("UpdateClient_RepoSaveFails", func(t *testing.T) {
		mockOAuthRepo := new(MockOAuthRepository)
		service := NewClientManagementServer(mockOAuthRepo, mockHasher)
		mockOAuthRepo.On("GetClient", ctx, clientID).Return(originalClient, nil).Once()
		mockOAuthRepo.On("UpdateClient", ctx, mock.AnythingOfType("*client.Client")).Return(errors.New("db update error")).Once()

		req := connect.NewRequest(&ssov1.UpdateClientRequest{ClientId: clientID, ClientName: "name change"})
		_, err := service.UpdateClient(ctx, req)
		require.Error(t, err)
		connectErr, ok := err.(*connect.Error)
		require.True(t, ok)
		assert.Equal(t, connect.CodeInternal, connectErr.Code())
		mockOAuthRepo.AssertExpectations(t)
	})
}

func TestClientManagementServer_DeleteClient(t *testing.T) {
	mockOAuthRepo := new(MockOAuthRepository)
	service := NewClientManagementServer(mockOAuthRepo, nil) // Hasher not used
	ctx := context.Background()
	clientID := "client-to-delete"

	t.Run("Successful DeleteClient", func(t *testing.T) {
		mockOAuthRepo := new(MockOAuthRepository)
		service := NewClientManagementServer(mockOAuthRepo, nil)
		mockOAuthRepo.On("DeleteClient", ctx, clientID).Return(nil).Once()

		req := connect.NewRequest(&ssov1.DeleteClientRequest{ClientId: clientID})
		_, err := service.DeleteClient(ctx, req)
		require.NoError(t, err)
		mockOAuthRepo.AssertExpectations(t)
	})

	t.Run("DeleteClient_NotFound", func(t *testing.T) {
		mockOAuthRepo := new(MockOAuthRepository)
		service := NewClientManagementServer(mockOAuthRepo, nil)
		mockOAuthRepo.On("DeleteClient", ctx, clientID).Return(errors.New("mongo: no documents in result (not found)")).Once()

		req := connect.NewRequest(&ssov1.DeleteClientRequest{ClientId: clientID})
		_, err := service.DeleteClient(ctx, req)
		require.Error(t, err)
		connectErr, ok := err.(*connect.Error)
		require.True(t, ok)
		// The service layer converts "not found" from repo to connect.CodeNotFound
		assert.Equal(t, connect.CodeNotFound, connectErr.Code())
		mockOAuthRepo.AssertExpectations(t)
	})

	t.Run("DeleteClient_RepoError", func(t *testing.T) {
		mockOAuthRepo := new(MockOAuthRepository)
		service := NewClientManagementServer(mockOAuthRepo, nil)
		mockOAuthRepo.On("DeleteClient", ctx, clientID).Return(errors.New("some db error")).Once()

		req := connect.NewRequest(&ssov1.DeleteClientRequest{ClientId: clientID})
		_, err := service.DeleteClient(ctx, req)
		require.Error(t, err)
		connectErr, ok := err.(*connect.Error)
		require.True(t, ok)
		assert.Equal(t, connect.CodeInternal, connectErr.Code())
		mockOAuthRepo.AssertExpectations(t)
	})
}
