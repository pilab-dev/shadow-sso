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

func TestProtocolMapperService_CreateRealmAndClientMappers(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mapperRepo := mock_domain.NewMockProtocolMapperRepository(ctrl)
	clientRepo := mock_domain.NewMockClientRepository(ctrl)
	server := NewProtocolMapperServer(mapperRepo, clientRepo)

	clientRepo.EXPECT().GetClient(gomock.Any(), "client-a").Return(&domain.Client{ID: "client-a"}, nil).Times(1)
	mapperRepo.EXPECT().CreateProtocolMapper(gomock.Any(), gomock.Any()).DoAndReturn(
		func(_ context.Context, m *domain.ProtocolMapper) error {
			m.ID = "mapper-1"
			require.Equal(t, "openid-connect", m.Protocol, "protocol must default to openid-connect")
			require.Equal(t, "value", m.Config["claim.value"], "config values are stored as strings")
			return nil
		}).Times(1)

	resp, err := server.CreateProtocolMapper(context.Background(), connect.NewRequest(&ssov1.CreateProtocolMapperRequest{
		Name:           "client-claim",
		ProtocolMapper: "oidc-hardcoded-claim-mapper",
		Config:         map[string]string{"claim.name": "tenant", "claim.value": "value"},
		ClientId:       ptr("client-a"),
	}))
	require.NoError(t, err)
	assert.Equal(t, "client-a", resp.Msg.ProtocolMapper.ClientId)
	assert.Equal(t, "mapper-1", resp.Msg.ProtocolMapper.Id)

	// Omitted client_id creates a realm-wide mapper and skips client lookup.
	mapperRepo.EXPECT().CreateProtocolMapper(gomock.Any(), gomock.Any()).DoAndReturn(
		func(_ context.Context, m *domain.ProtocolMapper) error {
			require.Empty(t, m.ClientID)
			return nil
		}).Times(1)
	realmResp, err := server.CreateProtocolMapper(context.Background(), connect.NewRequest(&ssov1.CreateProtocolMapperRequest{
		Name:           "realm-claim",
		ProtocolMapper: "oidc-hardcoded-claim-mapper",
	}))
	require.NoError(t, err)
	assert.Empty(t, realmResp.Msg.ProtocolMapper.ClientId)
}

func TestProtocolMapperService_CreateRejectsUnknownClient(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	clientRepo := mock_domain.NewMockClientRepository(ctrl)
	clientRepo.EXPECT().GetClient(gomock.Any(), "missing").Return(nil, errors.New("not found"))
	server := NewProtocolMapperServer(mock_domain.NewMockProtocolMapperRepository(ctrl), clientRepo)

	_, err := server.CreateProtocolMapper(context.Background(), connect.NewRequest(&ssov1.CreateProtocolMapperRequest{
		Name:           "claim",
		ProtocolMapper: "oidc-hardcoded-claim-mapper",
		ClientId:       ptr("missing"),
	}))
	require.Error(t, err)
	assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err))
}

func TestProtocolMapperService_ListFilters(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mapperRepo := mock_domain.NewMockProtocolMapperRepository(ctrl)
	server := NewProtocolMapperServer(mapperRepo, nil)

	mapperRepo.EXPECT().ListClientProtocolMappers(gomock.Any(), "client-a").Return([]*domain.ProtocolMapper{
		{ID: "b", Name: "b"},
		{ID: "a", Name: "a"},
	}, nil)
	resp, err := server.ListProtocolMappers(context.Background(), connect.NewRequest(&ssov1.ListProtocolMappersRequest{
		ClientId: "client-a",
	}))
	require.NoError(t, err)
	require.Len(t, resp.Msg.ProtocolMappers, 2)
	assert.Equal(t, "a", resp.Msg.ProtocolMappers[0].Id, "results are sorted by name")

	mapperRepo.EXPECT().ListRealmProtocolMappers(gomock.Any()).Return([]*domain.ProtocolMapper{{ID: "r", Name: "realm"}}, nil)
	realmResp, err := server.ListProtocolMappers(context.Background(), connect.NewRequest(&ssov1.ListProtocolMappersRequest{
		RealmOnly: true,
	}))
	require.NoError(t, err)
	require.Len(t, realmResp.Msg.ProtocolMappers, 1)

	_, err = server.ListProtocolMappers(context.Background(), connect.NewRequest(&ssov1.ListProtocolMappersRequest{
		ClientId:  "client-a",
		RealmOnly: true,
	}))
	require.Error(t, err)
	assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err))
}

func TestProtocolMapperService_UpdateMovesMapperBetweenScopes(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mapperRepo := mock_domain.NewMockProtocolMapperRepository(ctrl)
	server := NewProtocolMapperServer(mapperRepo, nil)

	mapperRepo.EXPECT().GetProtocolMapperByID(gomock.Any(), "mapper-1").Return(&domain.ProtocolMapper{
		ID:             "mapper-1",
		Name:           "claim",
		Protocol:       "openid-connect",
		ProtocolMapper: "oidc-hardcoded-claim-mapper",
		ClientID:       "client-a",
		Config:         map[string]any{"claim.name": "tenant", "claim.value": "x"},
	}, nil)
	mapperRepo.EXPECT().UpdateProtocolMapper(gomock.Any(), gomock.Any()).DoAndReturn(
		func(_ context.Context, m *domain.ProtocolMapper) error {
			require.Empty(t, m.ClientID, "empty client_id must move the mapper to realm level")
			require.Equal(t, "updated", m.Config["claim.value"])
			return nil
		})

	resp, err := server.UpdateProtocolMapper(context.Background(), connect.NewRequest(&ssov1.UpdateProtocolMapperRequest{
		Id:          "mapper-1",
		ClientId:    ptr(""),
		Config:      map[string]string{"claim.name": "tenant", "claim.value": "updated"},
		ClearConfig: false,
	}))
	require.NoError(t, err)
	assert.Empty(t, resp.Msg.ProtocolMapper.ClientId)
}

func TestProtocolMapperService_UpdateClearConfig(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mapperRepo := mock_domain.NewMockProtocolMapperRepository(ctrl)
	server := NewProtocolMapperServer(mapperRepo, nil)

	mapperRepo.EXPECT().GetProtocolMapperByID(gomock.Any(), "mapper-1").Return(&domain.ProtocolMapper{
		ID: "mapper-1", Name: "claim", Protocol: "openid-connect",
		ProtocolMapper: "oidc-hardcoded-claim-mapper",
		Config:         map[string]any{"claim.name": "tenant"},
	}, nil)
	mapperRepo.EXPECT().UpdateProtocolMapper(gomock.Any(), gomock.Any()).DoAndReturn(
		func(_ context.Context, m *domain.ProtocolMapper) error {
			require.Nil(t, m.Config)
			return nil
		})

	_, err := server.UpdateProtocolMapper(context.Background(), connect.NewRequest(&ssov1.UpdateProtocolMapperRequest{
		Id:          "mapper-1",
		ClearConfig: true,
	}))
	require.NoError(t, err)
}

func TestProtocolMapperService_ListPagination(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mapperRepo := mock_domain.NewMockProtocolMapperRepository(ctrl)
	server := NewProtocolMapperServer(mapperRepo, nil)

	mappers := make([]*domain.ProtocolMapper, 3)
	for i := range mappers {
		mappers[i] = &domain.ProtocolMapper{ID: string(rune('a' + i)), Name: string(rune('a' + i))}
	}
	mapperRepo.EXPECT().ListProtocolMappers(gomock.Any()).Return(mappers, nil).Times(2)

	first, err := server.ListProtocolMappers(context.Background(), connect.NewRequest(&ssov1.ListProtocolMappersRequest{PageSize: 2}))
	require.NoError(t, err)
	require.Len(t, first.Msg.ProtocolMappers, 2)
	require.NotEmpty(t, first.Msg.NextPageToken)

	second, err := server.ListProtocolMappers(context.Background(), connect.NewRequest(&ssov1.ListProtocolMappersRequest{
		PageSize: 2, PageToken: first.Msg.NextPageToken,
	}))
	require.NoError(t, err)
	require.Len(t, second.Msg.ProtocolMappers, 1)
	require.Empty(t, second.Msg.NextPageToken)
}

func TestProtocolMapperService_DeleteReportsNotFound(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mapperRepo := mock_domain.NewMockProtocolMapperRepository(ctrl)
	mapperRepo.EXPECT().DeleteProtocolMapper(gomock.Any(), "missing").Return(errors.New("protocol mapper not found: missing"))
	server := NewProtocolMapperServer(mapperRepo, nil)

	_, err := server.DeleteProtocolMapper(context.Background(), connect.NewRequest(&ssov1.DeleteProtocolMapperRequest{Id: "missing"}))
	require.Error(t, err)
	assert.Equal(t, connect.CodeNotFound, connect.CodeOf(err))
}

func ptr[T any](v T) *T { return &v }
