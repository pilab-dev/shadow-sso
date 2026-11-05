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

func newRoleTestServer(t *testing.T) (*RoleServiceServer, *mock_domain.MockRoleRepository, *mock_domain.MockUserRepository) {
	ctrl := gomock.NewController(t)
	roles := mock_domain.NewMockRoleRepository(ctrl)
	users := mock_domain.NewMockUserRepository(ctrl)
	return NewRoleServer(roles, users), roles, users
}

func TestRoleService_CreateAndValidation(t *testing.T) {
	server, roles, _ := newRoleTestServer(t)
	roles.EXPECT().CreateRole(gomock.Any(), gomock.Any()).DoAndReturn(
		func(_ context.Context, r *domain.Role) error {
			r.ID = "r1"
			require.True(t, r.ClientRole)
			require.Equal(t, "app", r.ContainerID)
			return nil
		})

	resp, err := server.CreateRole(context.Background(), connect.NewRequest(&ssov1.CreateRoleRequest{
		Name: "editor", ClientRole: true, ClientId: "app",
	}))
	require.NoError(t, err)
	assert.Equal(t, "r1", resp.Msg.Role.Id)

	_, err = server.CreateRole(context.Background(), connect.NewRequest(&ssov1.CreateRoleRequest{Name: " "}))
	assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err))
}

func TestRoleService_GetNotFoundAndList(t *testing.T) {
	server, roles, _ := newRoleTestServer(t)
	roles.EXPECT().GetRoleByID(gomock.Any(), "missing").Return(nil, errors.New("role not found"))
	roles.EXPECT().ListRoles(gomock.Any()).Return([]*domain.Role{{ID: "1", Name: "a"}, {ID: "2", Name: "b"}}, nil)

	_, err := server.GetRole(context.Background(), connect.NewRequest(&ssov1.GetRoleRequest{Id: "missing"}))
	assert.Equal(t, connect.CodeNotFound, connect.CodeOf(err))

	resp, err := server.ListRoles(context.Background(), connect.NewRequest(&ssov1.ListRolesRequest{}))
	require.NoError(t, err)
	assert.Len(t, resp.Msg.Roles, 2)
}

func TestRoleService_UpdateAndDelete(t *testing.T) {
	server, roles, _ := newRoleTestServer(t)
	roles.EXPECT().GetRoleByID(gomock.Any(), "r1").Return(&domain.Role{ID: "r1", Name: "old"}, nil)
	roles.EXPECT().UpdateRole(gomock.Any(), gomock.Any()).Return(nil)
	roles.EXPECT().DeleteRole(gomock.Any(), "r1").Return(nil)

	resp, err := server.UpdateRole(context.Background(), connect.NewRequest(&ssov1.UpdateRoleRequest{Id: "r1", Name: ptr("new")}))
	require.NoError(t, err)
	assert.Equal(t, "new", resp.Msg.Role.Name)

	_, err = server.UpdateRole(context.Background(), connect.NewRequest(&ssov1.UpdateRoleRequest{Id: "r1"}))
	assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err))

	_, err = server.DeleteRole(context.Background(), connect.NewRequest(&ssov1.DeleteRoleRequest{Id: "r1"}))
	require.NoError(t, err)
}

func TestRoleService_CreateCompositeRole(t *testing.T) {
	server, roles, _ := newRoleTestServer(t)
	roles.EXPECT().CreateRole(gomock.Any(), gomock.Any()).DoAndReturn(
		func(_ context.Context, r *domain.Role) error { r.ID = "p"; return nil })
	roles.EXPECT().AddChildRole(gomock.Any(), "p", "c1").Return(nil)
	roles.EXPECT().AddChildRole(gomock.Any(), "p", "c2").Return(nil)

	resp, err := server.CreateCompositeRole(context.Background(), connect.NewRequest(&ssov1.CreateCompositeRoleRequest{
		Name:         "super",
		RealmRoleIds: []string{"c1"},
		ClientRoles:  []*ssov1.ClientRoleRef{{ClientId: "app", RoleId: "c2"}},
	}))
	require.NoError(t, err)
	assert.True(t, resp.Msg.Role.Composite)
	assert.Equal(t, []string{"c1", "c2"}, resp.Msg.Role.ChildRoleIds)
}

func TestRoleService_AddAndRemoveRealmRoleToUser(t *testing.T) {
	server, roles, users := newRoleTestServer(t)
	user := &domain.User{ID: "u1"}
	roles.EXPECT().GetRoleByID(gomock.Any(), "r1").Return(&domain.Role{ID: "r1", Name: "admin"}, nil).Times(3)
	users.EXPECT().GetUserByID(gomock.Any(), "u1").Return(user, nil).Times(3)
	users.EXPECT().UpdateUser(gomock.Any(), user).Return(nil).Times(2)

	add := connect.NewRequest(&ssov1.AddRealmRoleToUserRequest{UserId: "u1", RoleId: "r1"})
	_, err := server.AddRealmRoleToUser(context.Background(), add)
	require.NoError(t, err)
	assert.Equal(t, []string{"admin"}, user.Roles)

	// Idempotent: no second UpdateUser.
	_, err = server.AddRealmRoleToUser(context.Background(), add)
	require.NoError(t, err)
	assert.Equal(t, []string{"admin"}, user.Roles)

	_, err = server.RemoveRealmRoleFromUser(context.Background(), connect.NewRequest(&ssov1.RemoveRealmRoleFromUserRequest{UserId: "u1", RoleId: "r1"}))
	require.NoError(t, err)
	assert.Empty(t, user.Roles)
}

func TestRoleService_UserMappingsUserNotFound(t *testing.T) {
	server, _, users := newRoleTestServer(t)
	users.EXPECT().GetUserByID(gomock.Any(), "nope").Return(nil, errors.New("user not found"))

	_, err := server.GetUserRoleMappings(context.Background(), connect.NewRequest(&ssov1.GetUserRoleMappingsRequest{UserId: "nope"}))
	assert.Equal(t, connect.CodeNotFound, connect.CodeOf(err))
}

func TestRoleService_UserRoleMappingsResolveNames(t *testing.T) {
	server, roles, users := newRoleTestServer(t)
	users.EXPECT().GetUserByID(gomock.Any(), "u1").Return(&domain.User{
		ID: "u1", Roles: []string{"admin", "ghost"}, ClientRoles: map[string][]string{"app": {"editor"}},
	}, nil)
	roles.EXPECT().GetRoleByName(gomock.Any(), "admin").Return(&domain.Role{ID: "1", Name: "admin"}, nil)
	roles.EXPECT().GetRoleByName(gomock.Any(), "ghost").Return(nil, errors.New("not found"))
	roles.EXPECT().GetRoleByName(gomock.Any(), "editor").Return(&domain.Role{ID: "2", Name: "editor"}, nil)

	resp, err := server.GetUserRoleMappings(context.Background(), connect.NewRequest(&ssov1.GetUserRoleMappingsRequest{UserId: "u1"}))
	require.NoError(t, err)
	assert.Len(t, resp.Msg.RealmMappings, 1)
	assert.Len(t, resp.Msg.ClientMappings, 1)
}
