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

func newGroupTestServer(t *testing.T) (*GroupServiceServer, *mock_domain.MockGroupRepository, *mock_domain.MockRoleRepository, *mock_domain.MockUserRepository) {
	ctrl := gomock.NewController(t)
	groups := mock_domain.NewMockGroupRepository(ctrl)
	roles := mock_domain.NewMockRoleRepository(ctrl)
	users := mock_domain.NewMockUserRepository(ctrl)
	return NewGroupServer(groups, roles, users), groups, roles, users
}

func TestGroupService_CreateDefaultsPath(t *testing.T) {
	server, groups, _, _ := newGroupTestServer(t)
	groups.EXPECT().CreateGroup(gomock.Any(), gomock.Any()).DoAndReturn(
		func(_ context.Context, g *domain.Group) error {
			g.ID = "g1"
			require.Equal(t, "/staff", g.Path)
			return nil
		})

	resp, err := server.CreateGroup(context.Background(), connect.NewRequest(&ssov1.CreateGroupRequest{Name: "staff"}))
	require.NoError(t, err)
	assert.Equal(t, "g1", resp.Msg.Group.Id)

	_, err = server.CreateGroup(context.Background(), connect.NewRequest(&ssov1.CreateGroupRequest{Name: ""}))
	assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err))
}

func TestGroupService_GetNotFoundAndList(t *testing.T) {
	server, groups, _, _ := newGroupTestServer(t)
	groups.EXPECT().GetGroupByID(gomock.Any(), "x").Return(nil, errors.New("group not found"))
	groups.EXPECT().ListGroups(gomock.Any()).Return([]*domain.Group{{ID: "1", MemberIDs: []string{"u"}}}, nil)

	_, err := server.GetGroup(context.Background(), connect.NewRequest(&ssov1.GetGroupRequest{Id: "x"}))
	assert.Equal(t, connect.CodeNotFound, connect.CodeOf(err))

	resp, err := server.ListGroups(context.Background(), connect.NewRequest(&ssov1.ListGroupsRequest{}))
	require.NoError(t, err)
	require.Len(t, resp.Msg.Groups, 1)
	assert.Equal(t, int32(1), resp.Msg.Groups[0].MemberCount)
}

func TestGroupService_UpdateAndDelete(t *testing.T) {
	server, groups, _, _ := newGroupTestServer(t)
	groups.EXPECT().GetGroupByID(gomock.Any(), "g1").Return(&domain.Group{ID: "g1", Name: "a", Path: "/a"}, nil)
	groups.EXPECT().UpdateGroup(gomock.Any(), gomock.Any()).Return(nil)
	groups.EXPECT().DeleteGroup(gomock.Any(), "g1").Return(nil)

	resp, err := server.UpdateGroup(context.Background(), connect.NewRequest(&ssov1.UpdateGroupRequest{Id: "g1", Name: ptr("b")}))
	require.NoError(t, err)
	assert.Equal(t, "b", resp.Msg.Group.Name)
	assert.Equal(t, "/a", resp.Msg.Group.Path)

	_, err = server.UpdateGroup(context.Background(), connect.NewRequest(&ssov1.UpdateGroupRequest{Id: "g1"}))
	assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err))

	_, err = server.DeleteGroup(context.Background(), connect.NewRequest(&ssov1.DeleteGroupRequest{Id: "g1"}))
	require.NoError(t, err)
}

func TestGroupService_MembershipAndRoleMappings(t *testing.T) {
	server, groups, _, _ := newGroupTestServer(t)
	groups.EXPECT().AddMember(gomock.Any(), "g1", "u1").Return(nil)
	groups.EXPECT().RemoveMember(gomock.Any(), "g1", "missing").Return(errors.New("group not found"))
	groups.EXPECT().AddClientRole(gomock.Any(), "g1", "app", "r1").Return(nil)

	_, err := server.AddUserToGroup(context.Background(), connect.NewRequest(&ssov1.AddUserToGroupRequest{UserId: "u1", GroupId: "g1"}))
	require.NoError(t, err)

	_, err = server.RemoveUserFromGroup(context.Background(), connect.NewRequest(&ssov1.RemoveUserFromGroupRequest{UserId: "missing", GroupId: "g1"}))
	assert.Equal(t, connect.CodeNotFound, connect.CodeOf(err))

	_, err = server.AddClientRoleToGroup(context.Background(), connect.NewRequest(&ssov1.AddClientRoleToGroupRequest{GroupId: "g1", ClientId: "app", RoleId: "r1"}))
	require.NoError(t, err)
}

func TestGroupService_ListMembersAndRoles(t *testing.T) {
	server, groups, roles, users := newGroupTestServer(t)
	group := &domain.Group{ID: "g1", MemberIDs: []string{"u1", "gone"}, RealmRoles: []string{"r1"}, ClientRoles: map[string][]string{"app": {"r2"}}}
	groups.EXPECT().GetGroupByID(gomock.Any(), "g1").Return(group, nil).Times(2)
	users.EXPECT().GetUserByID(gomock.Any(), "u1").Return(&domain.User{ID: "u1", Email: "a@b.c"}, nil)
	users.EXPECT().GetUserByID(gomock.Any(), "gone").Return(nil, errors.New("user not found"))
	roles.EXPECT().GetRoleByID(gomock.Any(), "r1").Return(&domain.Role{ID: "r1", Name: "realm"}, nil)
	roles.EXPECT().GetRoleByID(gomock.Any(), "r2").Return(&domain.Role{ID: "r2", Name: "client"}, nil)

	members, err := server.ListGroupMembers(context.Background(), connect.NewRequest(&ssov1.ListGroupMembersRequest{GroupId: "g1"}))
	require.NoError(t, err)
	require.Len(t, members.Msg.Members, 1)
	assert.Equal(t, int32(2), members.Msg.TotalCount)

	rr, err := server.GetGroupRoles(context.Background(), connect.NewRequest(&ssov1.GetGroupRolesRequest{GroupId: "g1"}))
	require.NoError(t, err)
	assert.Len(t, rr.Msg.RealmRoles, 1)
	assert.Len(t, rr.Msg.ClientRoles["app"].Roles, 1)
}
