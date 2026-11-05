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

func TestAuthenticationFlowService_CreateAndList(t *testing.T) {
	ctrl := gomock.NewController(t)
	repo := mock_domain.NewMockAuthenticationFlowRepository(ctrl)
	repo.EXPECT().CreateFlow(gomock.Any(), gomock.Any()).DoAndReturn(
		func(_ context.Context, f *domain.AuthenticationFlow) error {
			f.ID = "f1"
			assert.True(t, f.TopLevel)
			return nil
		})
	repo.EXPECT().ListFlows(gomock.Any()).Return([]*domain.AuthenticationFlow{{ID: "f1", Alias: "browser"}}, nil)
	s := NewAuthenticationFlowServer(repo)

	created, err := s.CreateAuthenticationFlow(context.Background(), connect.NewRequest(&ssov1.CreateAuthenticationFlowRequest{
		Alias: "browser", DisplayName: "Browser", TopLevel: true,
	}))
	require.NoError(t, err)
	assert.Equal(t, "f1", created.Msg.Flow.Id)

	list, err := s.ListAuthenticationFlows(context.Background(), connect.NewRequest(&ssov1.ListAuthenticationFlowsRequest{}))
	require.NoError(t, err)
	require.Len(t, list.Msg.Flows, 1)
	assert.Equal(t, "browser", list.Msg.Flows[0].Alias)
}

func TestAuthenticationFlowService_CreateValidation(t *testing.T) {
	s := NewAuthenticationFlowServer(mock_domain.NewMockAuthenticationFlowRepository(gomock.NewController(t)))
	_, err := s.CreateAuthenticationFlow(context.Background(), connect.NewRequest(&ssov1.CreateAuthenticationFlowRequest{}))
	assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err))
}

func TestAuthenticationFlowService_UpdatePatchesAndNotFound(t *testing.T) {
	ctrl := gomock.NewController(t)
	repo := mock_domain.NewMockAuthenticationFlowRepository(ctrl)
	repo.EXPECT().GetFlowByID(gomock.Any(), "f1").Return(&domain.AuthenticationFlow{ID: "f1", Alias: "a", DisplayName: "A"}, nil)
	repo.EXPECT().UpdateFlow(gomock.Any(), gomock.Any()).Return(nil)
	repo.EXPECT().GetFlowByID(gomock.Any(), "nope").Return(nil, errors.New("flow not found"))
	s := NewAuthenticationFlowServer(repo)

	name := "New"
	resp, err := s.UpdateAuthenticationFlow(context.Background(), connect.NewRequest(&ssov1.UpdateAuthenticationFlowRequest{Id: "f1", DisplayName: &name}))
	require.NoError(t, err)
	assert.Equal(t, "New", resp.Msg.Flow.DisplayName)
	assert.Equal(t, "a", resp.Msg.Flow.Alias)

	_, err = s.UpdateAuthenticationFlow(context.Background(), connect.NewRequest(&ssov1.UpdateAuthenticationFlowRequest{Id: "nope"}))
	assert.Equal(t, connect.CodeNotFound, connect.CodeOf(err))
}

func TestAuthenticationFlowService_DeleteNotFound(t *testing.T) {
	repo := mock_domain.NewMockAuthenticationFlowRepository(gomock.NewController(t))
	repo.EXPECT().DeleteFlow(gomock.Any(), "x").Return(errors.New("not found"))
	s := NewAuthenticationFlowServer(repo)
	_, err := s.DeleteAuthenticationFlow(context.Background(), connect.NewRequest(&ssov1.DeleteAuthenticationFlowRequest{Id: "x"}))
	assert.Equal(t, connect.CodeNotFound, connect.CodeOf(err))
}

func TestAuthenticationFlowService_UpdateExecutions(t *testing.T) {
	ctrl := gomock.NewController(t)
	repo := mock_domain.NewMockAuthenticationFlowRepository(ctrl)
	repo.EXPECT().GetFlowByID(gomock.Any(), "f1").Return(&domain.AuthenticationFlow{ID: "f1"}, nil)
	repo.EXPECT().UpsertExecution(gomock.Any(), gomock.Any()).DoAndReturn(
		func(_ context.Context, e *domain.AuthenticationExecution) error {
			assert.Equal(t, "f1", e.FlowID)
			assert.Equal(t, "REQUIRED", e.Requirement)
			return nil
		})
	s := NewAuthenticationFlowServer(repo)

	_, err := s.UpdateAuthenticationExecutions(context.Background(), connect.NewRequest(&ssov1.UpdateAuthenticationExecutionsRequest{
		FlowId:     "f1",
		Executions: []*ssov1.AuthenticationExecutionInput{{Execution: "password", Requirement: "REQUIRED"}},
	}))
	require.NoError(t, err)

	_, err = s.UpdateAuthenticationExecutions(context.Background(), connect.NewRequest(&ssov1.UpdateAuthenticationExecutionsRequest{
		FlowId:     "f1",
		Executions: []*ssov1.AuthenticationExecutionInput{{Execution: "password"}},
	}))
	assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err))
}
