package services

import (
	"context"
	"errors"
	"strings"

	"connectrpc.com/connect"
	"github.com/pilab-dev/shadow-sso/domain"
	ssov1 "github.com/pilab-dev/shadow-sso/gen/proto/sso/v1"
	"github.com/pilab-dev/shadow-sso/gen/proto/sso/v1/ssov1connect"
	"github.com/pilab-dev/shadow-sso/internal/audit"
	"github.com/pilab-dev/shadow-sso/internal/telemetry"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const groupServiceTracerName = "group-service"

// GroupServiceServer implements ssov1.GroupService.
type GroupServiceServer struct {
	ssov1connect.UnimplementedGroupServiceHandler
	groupRepo domain.GroupRepository
	roleRepo  domain.RoleRepository
	userRepo  domain.UserRepository
}

// NewGroupServer creates the group admin service.
func NewGroupServer(groupRepo domain.GroupRepository, roleRepo domain.RoleRepository, userRepo domain.UserRepository) *GroupServiceServer {
	return &GroupServiceServer{groupRepo: groupRepo, roleRepo: roleRepo, userRepo: userRepo}
}

var _ ssov1connect.GroupServiceHandler = (*GroupServiceServer)(nil)

// CreateGroup creates a group; the path defaults to "/<name>".
func (s *GroupServiceServer) CreateGroup(ctx context.Context, req *connect.Request[ssov1.CreateGroupRequest]) (*connect.Response[ssov1.CreateGroupResponse], error) {
	ctx, span := telemetry.StartSpan(ctx, groupServiceTracerName, "CreateGroup",
		attribute.String("group.name", req.Msg.GetName()))
	defer span.End()

	if strings.TrimSpace(req.Msg.GetName()) == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("name is required"))
	}
	group := &domain.Group{Name: req.Msg.GetName(), Path: "/" + req.Msg.GetName()}
	if req.Msg.GetPath() != "" {
		group.Path = req.Msg.GetPath()
	}
	if err := s.groupRepo.CreateGroup(ctx, group); err != nil {
		telemetry.RecordSpanError(span, err, "failed to create group")
		return nil, repoError(span, err, "group", "create")
	}

	audit.Log("Group", "GroupCreated", "", group.ID, group.Name, true, nil)
	return connect.NewResponse(&ssov1.CreateGroupResponse{Group: toGroupProto(group)}), nil
}

// GetGroup returns one group by ID.
func (s *GroupServiceServer) GetGroup(ctx context.Context, req *connect.Request[ssov1.GetGroupRequest]) (*connect.Response[ssov1.GetGroupResponse], error) {
	ctx, span := telemetry.StartSpan(ctx, groupServiceTracerName, "GetGroup",
		attribute.String("group.id", req.Msg.GetId()))
	defer span.End()

	group, err := s.loadGroup(ctx, span, req.Msg.GetId())
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&ssov1.GetGroupResponse{Group: toGroupProto(group)}), nil
}

// ListGroups lists every group.
func (s *GroupServiceServer) ListGroups(ctx context.Context, _ *connect.Request[ssov1.ListGroupsRequest]) (*connect.Response[ssov1.ListGroupsResponse], error) {
	ctx, span := telemetry.StartSpan(ctx, groupServiceTracerName, "ListGroups")
	defer span.End()

	groups, err := s.groupRepo.ListGroups(ctx)
	if err != nil {
		telemetry.RecordSpanError(span, err, "failed to list groups")
		return nil, repoError(span, err, "groups", "list")
	}
	return connect.NewResponse(&ssov1.ListGroupsResponse{Groups: toGroupProtos(groups)}), nil
}

// UpdateGroup mutates an existing group.
func (s *GroupServiceServer) UpdateGroup(ctx context.Context, req *connect.Request[ssov1.UpdateGroupRequest]) (*connect.Response[ssov1.UpdateGroupResponse], error) {
	ctx, span := telemetry.StartSpan(ctx, groupServiceTracerName, "UpdateGroup",
		attribute.String("group.id", req.Msg.GetId()))
	defer span.End()

	if req.Msg.Name == nil && req.Msg.Path == nil {
		return nil, connect.NewError(connect.CodeInvalidArgument,
			errors.New("at least one field must be provided for update"))
	}
	if req.Msg.Name != nil && strings.TrimSpace(*req.Msg.Name) == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("name must not be empty"))
	}
	if req.Msg.Path != nil && strings.TrimSpace(*req.Msg.Path) == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("path must not be empty"))
	}

	group, err := s.loadGroup(ctx, span, req.Msg.GetId())
	if err != nil {
		return nil, err
	}
	if req.Msg.Name != nil {
		group.Name = *req.Msg.Name
	}
	if req.Msg.Path != nil {
		group.Path = *req.Msg.Path
	}
	if err := s.groupRepo.UpdateGroup(ctx, group); err != nil {
		telemetry.RecordSpanError(span, err, "failed to update group")
		return nil, repoError(span, err, "group", "update")
	}

	audit.Log("Group", "GroupUpdated", "", group.ID, group.Name, true, nil)
	return connect.NewResponse(&ssov1.UpdateGroupResponse{Group: toGroupProto(group)}), nil
}

// DeleteGroup removes a group.
func (s *GroupServiceServer) DeleteGroup(ctx context.Context, req *connect.Request[ssov1.DeleteGroupRequest]) (*connect.Response[emptypb.Empty], error) {
	ctx, span := telemetry.StartSpan(ctx, groupServiceTracerName, "DeleteGroup",
		attribute.String("group.id", req.Msg.GetId()))
	defer span.End()

	if err := s.groupRepo.DeleteGroup(ctx, req.Msg.GetId()); err != nil {
		telemetry.RecordSpanError(span, err, "failed to delete group")
		return nil, repoError(span, err, "group", "delete")
	}

	audit.Log("Group", "GroupDeleted", "", req.Msg.GetId(), "", true, nil)
	return connect.NewResponse(&emptypb.Empty{}), nil
}

// ListGroupMembers returns the (paginated) members of a group; unknown users are skipped.
func (s *GroupServiceServer) ListGroupMembers(ctx context.Context, req *connect.Request[ssov1.ListGroupMembersRequest]) (*connect.Response[ssov1.ListGroupMembersResponse], error) {
	ctx, span := telemetry.StartSpan(ctx, groupServiceTracerName, "ListGroupMembers",
		attribute.String("group.id", req.Msg.GetGroupId()))
	defer span.End()

	group, err := s.loadGroup(ctx, span, req.Msg.GetGroupId())
	if err != nil {
		return nil, err
	}
	page, nextToken := paginate(group.MemberIDs, pageOffsetFromToken(req.Msg.GetPageToken()), normalizePageSize(req.Msg.GetPageSize()))
	members := make([]*ssov1.GroupMember, 0, len(page))
	for _, id := range page {
		user, err := s.userRepo.GetUserByID(ctx, id)
		if err != nil || user == nil {
			continue
		}
		members = append(members, &ssov1.GroupMember{
			Id: user.ID, Email: user.Email, FirstName: user.FirstName, LastName: user.LastName,
		})
	}
	return connect.NewResponse(&ssov1.ListGroupMembersResponse{
		Members:       members,
		NextPageToken: nextToken,
		TotalCount:    int32(len(group.MemberIDs)),
	}), nil
}

// ListUserGroups returns the groups a user belongs to.
func (s *GroupServiceServer) ListUserGroups(ctx context.Context, req *connect.Request[ssov1.ListUserGroupsRequest]) (*connect.Response[ssov1.ListUserGroupsResponse], error) {
	ctx, span := telemetry.StartSpan(ctx, groupServiceTracerName, "ListUserGroups",
		attribute.String("user.id", req.Msg.GetUserId()))
	defer span.End()

	groups, err := s.groupRepo.GetGroupsByUserID(ctx, req.Msg.GetUserId())
	if err != nil {
		telemetry.RecordSpanError(span, err, "failed to list user groups")
		return nil, repoError(span, err, "groups", "list")
	}
	return connect.NewResponse(&ssov1.ListUserGroupsResponse{Groups: toGroupProtos(groups)}), nil
}

// AddUserToGroup adds a user to a group.
func (s *GroupServiceServer) AddUserToGroup(ctx context.Context, req *connect.Request[ssov1.AddUserToGroupRequest]) (*connect.Response[emptypb.Empty], error) {
	ctx, span := telemetry.StartSpan(ctx, groupServiceTracerName, "AddUserToGroup",
		attribute.String("group.id", req.Msg.GetGroupId()), attribute.String("user.id", req.Msg.GetUserId()))
	defer span.End()

	return s.groupMutation(span, "UserAddedToGroup", req.Msg.GetUserId(), req.Msg.GetGroupId(),
		s.groupRepo.AddMember(ctx, req.Msg.GetGroupId(), req.Msg.GetUserId()))
}

// RemoveUserFromGroup removes a user from a group.
func (s *GroupServiceServer) RemoveUserFromGroup(ctx context.Context, req *connect.Request[ssov1.RemoveUserFromGroupRequest]) (*connect.Response[emptypb.Empty], error) {
	ctx, span := telemetry.StartSpan(ctx, groupServiceTracerName, "RemoveUserFromGroup",
		attribute.String("group.id", req.Msg.GetGroupId()), attribute.String("user.id", req.Msg.GetUserId()))
	defer span.End()

	return s.groupMutation(span, "UserRemovedFromGroup", req.Msg.GetUserId(), req.Msg.GetGroupId(),
		s.groupRepo.RemoveMember(ctx, req.Msg.GetGroupId(), req.Msg.GetUserId()))
}

// GetGroupRoles returns the realm and client roles assigned to a group.
func (s *GroupServiceServer) GetGroupRoles(ctx context.Context, req *connect.Request[ssov1.GetGroupRolesRequest]) (*connect.Response[ssov1.GetGroupRolesResponse], error) {
	ctx, span := telemetry.StartSpan(ctx, groupServiceTracerName, "GetGroupRoles",
		attribute.String("group.id", req.Msg.GetGroupId()))
	defer span.End()

	group, err := s.loadGroup(ctx, span, req.Msg.GetGroupId())
	if err != nil {
		return nil, err
	}
	resp := &ssov1.GetGroupRolesResponse{
		RealmRoles:  toRoleProtos(s.resolveRoleIDs(ctx, group.RealmRoles)),
		ClientRoles: make(map[string]*ssov1.RoleList, len(group.ClientRoles)),
	}
	for clientID, ids := range group.ClientRoles {
		resp.ClientRoles[clientID] = &ssov1.RoleList{Roles: toRoleProtos(s.resolveRoleIDs(ctx, ids))}
	}
	return connect.NewResponse(resp), nil
}

// AddRealmRoleToGroup assigns a realm role to a group.
func (s *GroupServiceServer) AddRealmRoleToGroup(ctx context.Context, req *connect.Request[ssov1.AddRealmRoleToGroupRequest]) (*connect.Response[emptypb.Empty], error) {
	ctx, span := telemetry.StartSpan(ctx, groupServiceTracerName, "AddRealmRoleToGroup",
		attribute.String("group.id", req.Msg.GetGroupId()), attribute.String("role.id", req.Msg.GetRoleId()))
	defer span.End()

	return s.groupMutation(span, "RealmRoleAddedToGroup", "", req.Msg.GetGroupId(),
		s.groupRepo.AddRealmRole(ctx, req.Msg.GetGroupId(), req.Msg.GetRoleId()))
}

// RemoveRealmRoleFromGroup unassigns a realm role from a group.
func (s *GroupServiceServer) RemoveRealmRoleFromGroup(ctx context.Context, req *connect.Request[ssov1.RemoveRealmRoleFromGroupRequest]) (*connect.Response[emptypb.Empty], error) {
	ctx, span := telemetry.StartSpan(ctx, groupServiceTracerName, "RemoveRealmRoleFromGroup",
		attribute.String("group.id", req.Msg.GetGroupId()), attribute.String("role.id", req.Msg.GetRoleId()))
	defer span.End()

	return s.groupMutation(span, "RealmRoleRemovedFromGroup", "", req.Msg.GetGroupId(),
		s.groupRepo.RemoveRealmRole(ctx, req.Msg.GetGroupId(), req.Msg.GetRoleId()))
}

// AddClientRoleToGroup assigns a client role to a group.
func (s *GroupServiceServer) AddClientRoleToGroup(ctx context.Context, req *connect.Request[ssov1.AddClientRoleToGroupRequest]) (*connect.Response[emptypb.Empty], error) {
	ctx, span := telemetry.StartSpan(ctx, groupServiceTracerName, "AddClientRoleToGroup",
		attribute.String("group.id", req.Msg.GetGroupId()), attribute.String("client.id", req.Msg.GetClientId()),
		attribute.String("role.id", req.Msg.GetRoleId()))
	defer span.End()

	return s.groupMutation(span, "ClientRoleAddedToGroup", "", req.Msg.GetGroupId(),
		s.groupRepo.AddClientRole(ctx, req.Msg.GetGroupId(), req.Msg.GetClientId(), req.Msg.GetRoleId()))
}

// RemoveClientRoleFromGroup unassigns a client role from a group.
func (s *GroupServiceServer) RemoveClientRoleFromGroup(ctx context.Context, req *connect.Request[ssov1.RemoveClientRoleFromGroupRequest]) (*connect.Response[emptypb.Empty], error) {
	ctx, span := telemetry.StartSpan(ctx, groupServiceTracerName, "RemoveClientRoleFromGroup",
		attribute.String("group.id", req.Msg.GetGroupId()), attribute.String("client.id", req.Msg.GetClientId()),
		attribute.String("role.id", req.Msg.GetRoleId()))
	defer span.End()

	return s.groupMutation(span, "ClientRoleRemovedFromGroup", "", req.Msg.GetGroupId(),
		s.groupRepo.RemoveClientRole(ctx, req.Msg.GetGroupId(), req.Msg.GetClientId(), req.Msg.GetRoleId()))
}

// groupMutation converts a repository result of a membership/mapping change into a response.
func (s *GroupServiceServer) groupMutation(span interface {
	SetStatus(codes.Code, string)
}, event, actor, groupID string, err error) (*connect.Response[emptypb.Empty], error) {
	if err != nil {
		return nil, repoError(span, err, "group", "update")
	}
	audit.Log("Group", event, actor, groupID, "", true, nil)
	return connect.NewResponse(&emptypb.Empty{}), nil
}

func (s *GroupServiceServer) loadGroup(ctx context.Context, span interface {
	SetStatus(codes.Code, string)
}, id string) (*domain.Group, error) {
	group, err := s.groupRepo.GetGroupByID(ctx, id)
	if err != nil {
		return nil, repoError(span, err, "group", "retrieve")
	}
	if group == nil {
		return nil, connect.NewError(connect.CodeNotFound, errors.New("group not found"))
	}
	return group, nil
}

// resolveRoleIDs loads roles by ID, skipping IDs that no longer exist.
func (s *GroupServiceServer) resolveRoleIDs(ctx context.Context, ids []string) []*domain.Role {
	roles := make([]*domain.Role, 0, len(ids))
	for _, id := range ids {
		role, err := s.roleRepo.GetRoleByID(ctx, id)
		if err != nil || role == nil {
			continue
		}
		roles = append(roles, role)
	}
	return roles
}

func toGroupProtos(groups []*domain.Group) []*ssov1.Group {
	out := make([]*ssov1.Group, 0, len(groups))
	for _, g := range groups {
		if g != nil {
			out = append(out, toGroupProto(g))
		}
	}
	return out
}

func toGroupProto(group *domain.Group) *ssov1.Group {
	if group == nil {
		return nil
	}
	out := &ssov1.Group{
		Id:            group.ID,
		Name:          group.Name,
		Path:          group.Path,
		ParentGroupId: group.ParentGroupID,
		RealmRoleIds:  group.RealmRoles,
		MemberIds:     group.MemberIDs,
		MemberCount:   int32(len(group.MemberIDs)),
	}
	if len(group.ClientRoles) > 0 {
		out.ClientRoleIds = make(map[string]*ssov1.ClientRoleIds, len(group.ClientRoles))
		for clientID, ids := range group.ClientRoles {
			out.ClientRoleIds[clientID] = &ssov1.ClientRoleIds{RoleIds: ids}
		}
	}
	if !group.CreatedAt.IsZero() {
		out.CreatedAt = timestamppb.New(group.CreatedAt)
	}
	if !group.UpdatedAt.IsZero() {
		out.UpdatedAt = timestamppb.New(group.UpdatedAt)
	}
	return out
}
