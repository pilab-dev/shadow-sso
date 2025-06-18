package services

import (
	"context"
	"errors"
	// "fmt" // Not used in this snippet, but common
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
type MockIdPRepository struct {
	mock.Mock
}

func (m *MockIdPRepository) AddIdP(ctx context.Context, idp *domain.IdentityProvider) error {
	args := m.Called(ctx, idp)
	// Simulate ID generation if repo does it and idp.ID is empty
	if idpArg, ok := args.Get(1).(*domain.IdentityProvider); ok {
		if idpArg.ID == "" {
			idpArg.ID = "mock-idp-id"
		}
	}
	return args.Error(0)
}
func (m *MockIdPRepository) GetIdPByID(ctx context.Context, id string) (*domain.IdentityProvider, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.IdentityProvider), args.Error(1)
}
func (m *MockIdPRepository) GetIdPByName(ctx context.Context, name string) (*domain.IdentityProvider, error) {
	args := m.Called(ctx, name)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.IdentityProvider), args.Error(1)
}
func (m *MockIdPRepository) ListIdPs(ctx context.Context, onlyEnabled bool) ([]*domain.IdentityProvider, error) {
	args := m.Called(ctx, onlyEnabled)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*domain.IdentityProvider), args.Error(1)
}
func (m *MockIdPRepository) UpdateIdP(ctx context.Context, idp *domain.IdentityProvider) error {
	args := m.Called(ctx, idp)
	return args.Error(0)
}
func (m *MockIdPRepository) DeleteIdP(ctx context.Context, id string) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

// Helper for creating pointer to string, useful for optional proto fields
func protoStrPtr(s string) *string {
	if s == "" { // If empty string is meant to be "not set" for optional field
		return nil // This depends on how cmd flags differentiate empty from not-set
	}
	return &s
}


// --- IdPManagementServer Tests ---

func TestIdPManagementServer_AddIdP(t *testing.T) {
	// mockIdPRepo is defined per sub-test for isolation
	ctx := context.Background()

	reqMsg := &ssov1.AddIdPRequest{
		Name:             "TestOIDC_IdP",
		Type:             ssov1.IdPTypeProto_IDP_TYPE_OIDC,
		IsEnabled:        true,
		OidcClientId:     protoStrPtr("oidc-client-id-val"),
		OidcClientSecret: protoStrPtr("oidc-client-secret-val"),
		OidcIssuerUrl:    protoStrPtr("https://idp.example.com/oidc"),
		OidcScopes:       []string{"openid", "profile", "email"},
		AttributeMappings: []*ssov1.AttributeMappingProto{
			{ExternalAttributeName: "sub", LocalUserAttribute: "ExternalID"},
		},
	}

	t.Run("Successful AddIdP", func(t *testing.T) {
		mockIdPRepo := new(MockIdPRepository)
		service := NewIdPManagementServer(mockIdPRepo)
		var capturedIdP *domain.IdentityProvider

		mockIdPRepo.On("AddIdP", ctx, mock.AnythingOfType("*domain.IdentityProvider")).Run(func(args mock.Arguments) {
			capturedIdP = args.Get(1).(*domain.IdentityProvider)
			assert.Equal(t, reqMsg.Name, capturedIdP.Name)
			assert.Equal(t, domain.IdPTypeOIDC, capturedIdP.Type) // Check type mapping
			assert.Equal(t, reqMsg.GetOidcClientId(), capturedIdP.OIDCClientID)
			assert.Equal(t, reqMsg.GetOidcClientSecret(), capturedIdP.OIDCClientSecret)
		}).Return(nil).Once()

		resp, err := service.AddIdP(ctx, connect.NewRequest(reqMsg))

		require.NoError(t, err)
		require.NotNil(t, resp); require.NotNil(t, resp.Msg); require.NotNil(t, resp.Msg.Idp)
		assert.NotEmpty(t, resp.Msg.Idp.Id)
		assert.Equal(t, reqMsg.Name, resp.Msg.Idp.Name)
		assert.Equal(t, ssov1.IdPTypeProto_IDP_TYPE_OIDC, resp.Msg.Idp.Type)
		assert.Empty(t, resp.Msg.Idp.OidcClientSecret, "Secret should NOT be in AddIdP response")

		mockIdPRepo.AssertExpectations(t)
	})

	t.Run("AddIdP_RepoError", func(t *testing.T) {
		mockIdPRepo := new(MockIdPRepository)
		service := NewIdPManagementServer(mockIdPRepo)
		mockIdPRepo.On("AddIdP", ctx, mock.AnythingOfType("*domain.IdentityProvider")).Return(errors.New("db error")).Once()

		_, err := service.AddIdP(ctx, connect.NewRequest(reqMsg))
		require.Error(t, err)
		connectErr, ok := err.(*connect.Error)
		require.True(t, ok)
		assert.Equal(t, connect.CodeInternal, connectErr.Code())
		mockIdPRepo.AssertExpectations(t)
	})

	t.Run("AddIdP_DuplicateNameError", func(t *testing.T) {
		mockIdPRepo := new(MockIdPRepository)
		service := NewIdPManagementServer(mockIdPRepo)
		mockIdPRepo.On("AddIdP", ctx, mock.AnythingOfType("*domain.IdentityProvider")).Return(errors.New("IdP with this ID or Name already exists")).Once()

		_, err := service.AddIdP(ctx, connect.NewRequest(reqMsg))
		require.Error(t, err)
		connectErr, ok := err.(*connect.Error)
		require.True(t, ok)
		assert.Equal(t, connect.CodeAlreadyExists, connectErr.Code())
		mockIdPRepo.AssertExpectations(t)
	})
}

func TestIdPManagementServer_GetIdP(t *testing.T) {
	ctx := context.Background()
	idpID := "idp-test-id"
	dbIdP := &domain.IdentityProvider{
		ID:               idpID,
		Name:             "Fetched IdP",
		Type:             domain.IdPTypeOIDC,
		IsEnabled:        true,
		OIDCClientID:     "cid",
		OIDCClientSecret: "csecret_from_db_should_not_be_exposed",
		CreatedAt:        time.Now(),
		UpdatedAt:        time.Now(),
	}

	t.Run("Successful GetIdP", func(t *testing.T) {
		mockIdPRepo := new(MockIdPRepository)
		service := NewIdPManagementServer(mockIdPRepo)
		mockIdPRepo.On("GetIdPByID", ctx, idpID).Return(dbIdP, nil).Once()

		req := connect.NewRequest(&ssov1.GetIdPRequest{Id: idpID})
		resp, err := service.GetIdP(ctx, req)

		require.NoError(t, err)
		require.NotNil(t, resp); require.NotNil(t, resp.Msg); require.NotNil(t, resp.Msg.Idp)
		assert.Equal(t, idpID, resp.Msg.Idp.Id)
		assert.Equal(t, dbIdP.Name, resp.Msg.Idp.Name)
		assert.Empty(t, resp.Msg.Idp.OidcClientSecret, "Secret should be omitted in GetIdP response")
		mockIdPRepo.AssertExpectations(t)
	})

	t.Run("GetIdP_NotFound", func(t *testing.T) {
		mockIdPRepo := new(MockIdPRepository)
		service := NewIdPManagementServer(mockIdPRepo)
		mockIdPRepo.On("GetIdPByID", ctx, idpID).Return(nil, errors.New("identity provider not found by ID")).Once()

		req := connect.NewRequest(&ssov1.GetIdPRequest{Id: idpID})
		_, err := service.GetIdP(ctx, req)
		require.Error(t, err)
		connectErr, ok := err.(*connect.Error)
		require.True(t, ok)
		assert.Equal(t, connect.CodeNotFound, connectErr.Code())
		mockIdPRepo.AssertExpectations(t)
	})
}

// TODO: Add tests for ListIdPs, UpdateIdP, DeleteIdP

func TestIdPManagementServer_ListIdPs(t *testing.T) {
	ctx := context.Background()

	dbIdPs := []*domain.IdentityProvider{
		{ID: "idp1", Name: "IdP One", Type: domain.IdPTypeOIDC, IsEnabled: true, CreatedAt: time.Now()},
		{ID: "idp2", Name: "IdP Two", Type: domain.IdPTypeOIDC, IsEnabled: false, CreatedAt: time.Now()},
	}

	t.Run("Successful ListIdPs - All", func(t *testing.T) {
		mockIdPRepo := new(MockIdPRepository)
		service := NewIdPManagementServer(mockIdPRepo)
		mockIdPRepo.On("ListIdPs", ctx, false).Return(dbIdPs, nil).Once() // onlyEnabled = false

		req := connect.NewRequest(&ssov1.ListIdPsRequest{OnlyEnabled: false})
		resp, err := service.ListIdPs(ctx, req)

		require.NoError(t, err)
		require.NotNil(t, resp); require.NotNil(t, resp.Msg)
		assert.Len(t, resp.Msg.Idps, 2)
		if len(resp.Msg.Idps) == 2 {
			assert.Equal(t, dbIdPs[0].Name, resp.Msg.Idps[0].Name)
			assert.Equal(t, dbIdPs[1].Name, resp.Msg.Idps[1].Name)
			assert.Empty(t, resp.Msg.Idps[0].OidcClientSecret) // Ensure secret not exposed
		}
		mockIdPRepo.AssertExpectations(t)
	})

	t.Run("Successful ListIdPs - Only Enabled", func(t *testing.T) {
		mockIdPRepo := new(MockIdPRepository)
		service := NewIdPManagementServer(mockIdPRepo)
		enabledDbIdPs := []*domain.IdentityProvider{dbIdPs[0]} // Only idp1 is enabled
		mockIdPRepo.On("ListIdPs", ctx, true).Return(enabledDbIdPs, nil).Once() // onlyEnabled = true

		req := connect.NewRequest(&ssov1.ListIdPsRequest{OnlyEnabled: true})
		resp, err := service.ListIdPs(ctx, req)

		require.NoError(t, err)
		require.NotNil(t, resp); require.NotNil(t, resp.Msg)
		assert.Len(t, resp.Msg.Idps, 1)
		if len(resp.Msg.Idps) == 1 {
			assert.Equal(t, dbIdPs[0].Name, resp.Msg.Idps[0].Name)
		}
		mockIdPRepo.AssertExpectations(t)
	})

	t.Run("ListIdPs_RepoError", func(t *testing.T) {
		mockIdPRepo := new(MockIdPRepository)
		service := NewIdPManagementServer(mockIdPRepo)
		mockIdPRepo.On("ListIdPs", ctx, false).Return(nil, errors.New("db error")).Once()

		req := connect.NewRequest(&ssov1.ListIdPsRequest{OnlyEnabled: false})
		resp, err := service.ListIdPs(ctx, req)

		require.Error(t, err)
		assert.Nil(t, resp)
		connectErr, ok := err.(*connect.Error)
		require.True(t, ok)
		assert.Equal(t, connect.CodeInternal, connectErr.Code())
		mockIdPRepo.AssertExpectations(t)
	})
}

func TestIdPManagementServer_UpdateIdP(t *testing.T) {
	ctx := context.Background()
	idpID := "idp-to-update"
	originalUpdatedAt := time.Now().Add(-2 * time.Hour).UTC().Truncate(time.Millisecond)
	originalCreatedAt := time.Now().Add(-3 * time.Hour).UTC().Truncate(time.Millisecond)

	originalIdP := &domain.IdentityProvider{
		ID:               idpID,
		Name:             "Original IdP Name",
		Type:             domain.IdPTypeOIDC,
		IsEnabled:        true,
		OIDCClientID:     "orig-cid",
		OIDCClientSecret: "orig-secret", // This is the version in DB (e.g. encrypted)
		OIDCIssuerURL:    "https://orig.idp.com",
		OIDCScopes:       []string{"openid", "profile"},
		CreatedAt:        originalCreatedAt,
		UpdatedAt:        originalUpdatedAt,
	}

	updateReqMsg := &ssov1.UpdateIdPRequest{
		Id:               idpID,
		Name:             "Updated IdP Name",
		IsEnabled:        false,
		OidcClientId:     protoStrPtr("updated-cid"),
		OidcClientSecret: protoStrPtr("updated-secret-plaintext"), // New plaintext secret from user
		OidcIssuerUrl:    protoStrPtr("https://updated.idp.com"),
		OidcScopes:       []string{"openid", "email"},
		AttributeMappings: []*ssov1.AttributeMappingProto{
			{ExternalAttributeName: "uid", LocalUserAttribute: "UserID"},
		},
	}

	t.Run("Successful UpdateIdP", func(t *testing.T) {
		mockIdPRepo := new(MockIdPRepository)
		service := NewIdPManagementServer(mockIdPRepo)
		mockIdPRepo.On("GetIdPByID", ctx, idpID).Return(originalIdP, nil).Once()

		var capturedUpdate *domain.IdentityProvider
		mockIdPRepo.On("UpdateIdP", ctx, mock.AnythingOfType("*domain.IdentityProvider")).Run(func(args mock.Arguments) {
			capturedUpdate = args.Get(1).(*domain.IdentityProvider)
			assert.Equal(t, updateReqMsg.Name, capturedUpdate.Name)
			assert.Equal(t, updateReqMsg.GetOidcClientId(), capturedUpdate.OIDCClientID)
			// Service should pass the new secret to the repo (repo would handle encryption if any)
			assert.Equal(t, updateReqMsg.GetOidcClientSecret(), capturedUpdate.OIDCClientSecret)
			assert.False(t, capturedUpdate.IsEnabled)
			assert.Equal(t, updateReqMsg.OidcScopes, capturedUpdate.OIDCScopes)
			assert.Len(t, capturedUpdate.AttributeMappings, 1)
			if len(capturedUpdate.AttributeMappings) == 1 {
				assert.Equal(t, "uid", capturedUpdate.AttributeMappings[0].ExternalAttributeName)
			}
			assert.True(t, capturedUpdate.UpdatedAt.After(originalIdP.UpdatedAt))
		}).Return(nil).Once()

		resp, err := service.UpdateIdP(ctx, connect.NewRequest(updateReqMsg))

		require.NoError(t, err)
		require.NotNil(t, resp); require.NotNil(t, resp.Msg); require.NotNil(t, resp.Msg.Idp)
		assert.Equal(t, updateReqMsg.Name, resp.Msg.Idp.Name)
		assert.False(t, resp.Msg.Idp.IsEnabled)
		assert.Empty(t, resp.Msg.Idp.OidcClientSecret, "Secret should be omitted in UpdateIdP response")
		mockIdPRepo.AssertExpectations(t)
	})

	t.Run("UpdateIdP_NotFound", func(t *testing.T) {
		mockIdPRepo := new(MockIdPRepository)
		service := NewIdPManagementServer(mockIdPRepo)
		mockIdPRepo.On("GetIdPByID", ctx, idpID).Return(nil, errors.New("identity provider not found by ID")).Once()

		_, err := service.UpdateIdP(ctx, connect.NewRequest(updateReqMsg))
		require.Error(t, err)
		connectErr, ok := err.(*connect.Error)
		require.True(t, ok)
		assert.Equal(t, connect.CodeNotFound, connectErr.Code())
		mockIdPRepo.AssertExpectations(t)
		mockIdPRepo.AssertNotCalled(t, "UpdateIdP", mock.Anything, mock.Anything)
	})

	t.Run("UpdateIdP_RepoSaveFails", func(t *testing.T) {
		mockIdPRepo := new(MockIdPRepository)
		service := NewIdPManagementServer(mockIdPRepo)
		mockIdPRepo.On("GetIdPByID", ctx, idpID).Return(originalIdP, nil).Once()
		mockIdPRepo.On("UpdateIdP", ctx, mock.AnythingOfType("*domain.IdentityProvider")).Return(errors.New("db update error")).Once()

		_, err := service.UpdateIdP(ctx, connect.NewRequest(updateReqMsg))
		require.Error(t, err)
		connectErr, ok := err.(*connect.Error)
		require.True(t, ok)
		assert.Equal(t, connect.CodeInternal, connectErr.Code())
		mockIdPRepo.AssertExpectations(t)
	})
}

func TestIdPManagementServer_DeleteIdP(t *testing.T) {
	ctx := context.Background()
	idpID := "idp-to-delete"

	t.Run("Successful DeleteIdP", func(t *testing.T) {
		mockIdPRepo := new(MockIdPRepository)
		service := NewIdPManagementServer(mockIdPRepo)
		mockIdPRepo.On("DeleteIdP", ctx, idpID).Return(nil).Once()

		req := connect.NewRequest(&ssov1.DeleteIdPRequest{Id: idpID})
		_, err := service.DeleteIdP(ctx, req)
		require.NoError(t, err)
		mockIdPRepo.AssertExpectations(t)
	})

	t.Run("DeleteIdP_NotFound", func(t *testing.T) {
		mockIdPRepo := new(MockIdPRepository)
		service := NewIdPManagementServer(mockIdPRepo)
		mockIdPRepo.On("DeleteIdP", ctx, idpID).Return(errors.New("IdP configuration not found for deletion")).Once()

		req := connect.NewRequest(&ssov1.DeleteIdPRequest{Id: idpID})
		_, err := service.DeleteIdP(ctx, req)
		require.Error(t, err)
		connectErr, ok := err.(*connect.Error)
		require.True(t, ok)
		assert.Equal(t, connect.CodeNotFound, connectErr.Code())
		mockIdPRepo.AssertExpectations(t)
	})

	t.Run("DeleteIdP_RepoError", func(t *testing.T) {
		mockIdPRepo := new(MockIdPRepository)
		service := NewIdPManagementServer(mockIdPRepo)
		mockIdPRepo.On("DeleteIdP", ctx, idpID).Return(errors.New("some db error")).Once()

		req := connect.NewRequest(&ssov1.DeleteIdPRequest{Id: idpID})
		_, err := service.DeleteIdP(ctx, req)
		require.Error(t, err)
		connectErr, ok := err.(*connect.Error)
		require.True(t, ok)
		assert.Equal(t, connect.CodeInternal, connectErr.Code())
		mockIdPRepo.AssertExpectations(t)
	})
}
