package services

import (
	"context"
	"errors"
	"testing"

	"connectrpc.com/connect"
	"github.com/pilab-dev/shadow-sso/domain"
	mock_domain "github.com/pilab-dev/shadow-sso/domain/mocks"
	ssov1 "github.com/pilab-dev/shadow-sso/gen/proto/sso/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func TestClientScopeService_CreateDefaultsProtocol(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	repo := mock_domain.NewMockClientScopeRepository(ctrl)
	repo.EXPECT().CreateClientScope(gomock.Any(), gomock.Any()).DoAndReturn(
		func(_ context.Context, scope *domain.ClientScope) error {
			scope.ID = "scope-1"
			require.Equal(t, "openid-connect", scope.Protocol)
			require.Equal(t, 10, scope.DisplayOrder)
			return nil
		})
	server := NewClientScopeServer(repo)

	resp, err := server.CreateClientScope(context.Background(), connect.NewRequest(&ssov1.CreateClientScopeRequest{
		Name:         "tenant",
		DisplayOrder: ptr(int32(10)),
	}))
	require.NoError(t, err)
	assert.Equal(t, "scope-1", resp.Msg.ClientScope.Id)
	assert.Equal(t, "openid-connect", resp.Msg.ClientScope.Protocol)
	assert.Equal(t, int32(10), resp.Msg.ClientScope.DisplayOrder)
}

func TestClientScopeService_CreateRejectsEmptyName(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	server := NewClientScopeServer(mock_domain.NewMockClientScopeRepository(ctrl))
	_, err := server.CreateClientScope(context.Background(), connect.NewRequest(&ssov1.CreateClientScopeRequest{Name: "  "}))
	require.Error(t, err)
	assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err))
}

func TestClientScopeService_ListFiltersAndPaginates(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	repo := mock_domain.NewMockClientScopeRepository(ctrl)
	repo.EXPECT().ListClientScopes(gomock.Any()).Return([]*domain.ClientScope{
		{ID: "1", Name: "b", Protocol: "openid-connect", DisplayOrder: 2},
		{ID: "2", Name: "a", Protocol: "openid-connect", DisplayOrder: 1},
		{ID: "3", Name: "saml", Protocol: "saml", DisplayOrder: 3},
	}, nil).Times(2)
	server := NewClientScopeServer(repo)

	resp, err := server.ListClientScopes(context.Background(), connect.NewRequest(&ssov1.ListClientScopesRequest{
		Protocol: "openid-connect",
		PageSize: 1,
	}))
	require.NoError(t, err)
	require.Len(t, resp.Msg.ClientScopes, 1)
	assert.Equal(t, "2", resp.Msg.ClientScopes[0].Id, "scopes are sorted by display order")
	require.NotEmpty(t, resp.Msg.NextPageToken)

	resp2, err := server.ListClientScopes(context.Background(), connect.NewRequest(&ssov1.ListClientScopesRequest{
		Protocol:  "openid-connect",
		PageSize:  1,
		PageToken: resp.Msg.NextPageToken,
	}))
	require.NoError(t, err)
	require.Len(t, resp2.Msg.ClientScopes, 1)
	assert.Equal(t, "1", resp2.Msg.ClientScopes[0].Id)
}

func TestClientScopeService_UpdateAppliesOnlyProvidedFields(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	repo := mock_domain.NewMockClientScopeRepository(ctrl)
	repo.EXPECT().GetClientScopeByID(gomock.Any(), "scope-1").Return(&domain.ClientScope{
		ID: "scope-1", Name: "old", Description: "keep", Protocol: "openid-connect", DisplayOrder: 1,
	}, nil)
	repo.EXPECT().UpdateClientScope(gomock.Any(), gomock.Any()).DoAndReturn(
		func(_ context.Context, scope *domain.ClientScope) error {
			require.Equal(t, "new", scope.Name)
			require.Equal(t, "keep", scope.Description, "unset fields must be preserved")
			require.Equal(t, 5, scope.DisplayOrder)
			return nil
		})
	server := NewClientScopeServer(repo)

	resp, err := server.UpdateClientScope(context.Background(), connect.NewRequest(&ssov1.UpdateClientScopeRequest{
		Id:           "scope-1",
		Name:         ptr("new"),
		DisplayOrder: ptr(int32(5)),
	}))
	require.NoError(t, err)
	assert.Equal(t, "new", resp.Msg.ClientScope.Name)
}

func TestClientScopeService_UpdateRequiresAField(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	server := NewClientScopeServer(mock_domain.NewMockClientScopeRepository(ctrl))
	_, err := server.UpdateClientScope(context.Background(), connect.NewRequest(&ssov1.UpdateClientScopeRequest{Id: "scope-1"}))
	require.Error(t, err)
	assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err))
}

func TestClientScopeService_GetAndDeleteNotFound(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	repo := mock_domain.NewMockClientScopeRepository(ctrl)
	repo.EXPECT().GetClientScopeByID(gomock.Any(), "missing").Return(nil, errors.New("client scope not found: missing"))
	repo.EXPECT().DeleteClientScope(gomock.Any(), "missing").Return(errors.New("client scope not found: missing"))
	server := NewClientScopeServer(repo)

	_, err := server.GetClientScope(context.Background(), connect.NewRequest(&ssov1.GetClientScopeRequest{Id: "missing"}))
	require.Error(t, err)
	assert.Equal(t, connect.CodeNotFound, connect.CodeOf(err))

	_, err = server.DeleteClientScope(context.Background(), connect.NewRequest(&ssov1.DeleteClientScopeRequest{Id: "missing"}))
	require.Error(t, err)
	assert.Equal(t, connect.CodeNotFound, connect.CodeOf(err))
}
