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

const roleServiceTracerName = "role-service"

// RoleServiceServer implements ssov1.RoleService.
type RoleServiceServer struct {
	ssov1connect.UnimplementedRoleServiceHandler
	roleRepo domain.RoleRepository
	userRepo domain.UserRepository
}

// NewRoleServer creates the role admin service.
func NewRoleServer(roleRepo domain.RoleRepository, userRepo domain.UserRepository) *RoleServiceServer {
	return &RoleServiceServer{roleRepo: roleRepo, userRepo: userRepo}
}

var _ ssov1connect.RoleServiceHandler = (*RoleServiceServer)(nil)

// repoError maps a repository error to a connect error, hiding internals.
func repoError(span interface {
	SetStatus(codes.Code, string)
}, err error, entity, action string) error {
	span.SetStatus(codes.Error, action+" "+entity)
	if isNotFoundError(err) {
		return connect.NewError(connect.CodeNotFound, errors.New(entity+" not found"))
	}
	return connect.NewError(connect.CodeInternal, errors.New("failed to "+action+" "+entity))
}

// CreateRole creates a realm or client role.
func (s *RoleServiceServer) CreateRole(ctx context.Context, req *connect.Request[ssov1.CreateRoleRequest]) (*connect.Response[ssov1.CreateRoleResponse], error) {
	ctx, span := telemetry.StartSpan(ctx, roleServiceTracerName, "CreateRole",
		attribute.String("role.name", req.Msg.GetName()))
	defer span.End()

	if strings.TrimSpace(req.Msg.GetName()) == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("name is required"))
	}
	role := &domain.Role{
		Name:        req.Msg.GetName(),
		Description: req.Msg.GetDescription(),
		Composite:   req.Msg.GetComposite(),
		ClientRole:  req.Msg.GetClientRole(),
		ContainerID: req.Msg.GetClientId(),
	}
	if err := s.roleRepo.CreateRole(ctx, role); err != nil {
		telemetry.RecordSpanError(span, err, "failed to create role")
		return nil, repoError(span, err, "role", "create")
	}

	audit.Log("Role", "RoleCreated", "", role.ID, role.Name, true, nil)
	return connect.NewResponse(&ssov1.CreateRoleResponse{Role: toRoleProto(role)}), nil
}

// GetRole returns one role by ID.
func (s *RoleServiceServer) GetRole(ctx context.Context, req *connect.Request[ssov1.GetRoleRequest]) (*connect.Response[ssov1.GetRoleResponse], error) {
	ctx, span := telemetry.StartSpan(ctx, roleServiceTracerName, "GetRole",
		attribute.String("role.id", req.Msg.GetId()))
	defer span.End()

	role, err := s.roleRepo.GetRoleByID(ctx, req.Msg.GetId())
	if err != nil {
		telemetry.RecordSpanError(span, err, "failed to get role")
		return nil, repoError(span, err, "role", "retrieve")
	}
	if role == nil {
		return nil, connect.NewError(connect.CodeNotFound, errors.New("role not found"))
	}
	return connect.NewResponse(&ssov1.GetRoleResponse{Role: toRoleProto(role)}), nil
}

// ListRoles lists every role.
func (s *RoleServiceServer) ListRoles(ctx context.Context, _ *connect.Request[ssov1.ListRolesRequest]) (*connect.Response[ssov1.ListRolesResponse], error) {
	ctx, span := telemetry.StartSpan(ctx, roleServiceTracerName, "ListRoles")
	defer span.End()

	roles, err := s.roleRepo.ListRoles(ctx)
	if err != nil {
		telemetry.RecordSpanError(span, err, "failed to list roles")
		return nil, repoError(span, err, "roles", "list")
	}
	return connect.NewResponse(&ssov1.ListRolesResponse{Roles: toRoleProtos(roles)}), nil
}

// ListRealmRoles lists realm-level roles.
func (s *RoleServiceServer) ListRealmRoles(ctx context.Context, _ *connect.Request[ssov1.ListRealmRolesRequest]) (*connect.Response[ssov1.ListRealmRolesResponse], error) {
	ctx, span := telemetry.StartSpan(ctx, roleServiceTracerName, "ListRealmRoles")
	defer span.End()

	roles, err := s.roleRepo.ListRealmRoles(ctx)
	if err != nil {
		telemetry.RecordSpanError(span, err, "failed to list realm roles")
		return nil, repoError(span, err, "realm roles", "list")
	}
	return connect.NewResponse(&ssov1.ListRealmRolesResponse{Roles: toRoleProtos(roles)}), nil
}

// ListClientRoles lists roles owned by a client.
func (s *RoleServiceServer) ListClientRoles(ctx context.Context, req *connect.Request[ssov1.ListClientRolesRequest]) (*connect.Response[ssov1.ListClientRolesResponse], error) {
	ctx, span := telemetry.StartSpan(ctx, roleServiceTracerName, "ListClientRoles",
		attribute.String("client.id", req.Msg.GetClientId()))
	defer span.End()

	roles, err := s.roleRepo.ListClientRoles(ctx, req.Msg.GetClientId())
	if err != nil {
		telemetry.RecordSpanError(span, err, "failed to list client roles")
		return nil, repoError(span, err, "client roles", "list")
	}
	return connect.NewResponse(&ssov1.ListClientRolesResponse{Roles: toRoleProtos(roles)}), nil
}

// UpdateRole mutates an existing role.
func (s *RoleServiceServer) UpdateRole(ctx context.Context, req *connect.Request[ssov1.UpdateRoleRequest]) (*connect.Response[ssov1.UpdateRoleResponse], error) {
	ctx, span := telemetry.StartSpan(ctx, roleServiceTracerName, "UpdateRole",
		attribute.String("role.id", req.Msg.GetId()))
	defer span.End()

	if req.Msg.Name == nil && req.Msg.Description == nil && req.Msg.Composite == nil {
		return nil, connect.NewError(connect.CodeInvalidArgument,
			errors.New("at least one field must be provided for update"))
	}
	if req.Msg.Name != nil && strings.TrimSpace(*req.Msg.Name) == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("name must not be empty"))
	}

	role, err := s.roleRepo.GetRoleByID(ctx, req.Msg.GetId())
	if err != nil {
		telemetry.RecordSpanError(span, err, "failed to retrieve role for update")
		return nil, repoError(span, err, "role", "retrieve")
	}
	if role == nil {
		return nil, connect.NewError(connect.CodeNotFound, errors.New("role not found"))
	}

	if req.Msg.Name != nil {
		role.Name = *req.Msg.Name
	}
	if req.Msg.Description != nil {
		role.Description = *req.Msg.Description
	}
	if req.Msg.Composite != nil {
		role.Composite = *req.Msg.Composite
	}
	if err := s.roleRepo.UpdateRole(ctx, role); err != nil {
		telemetry.RecordSpanError(span, err, "failed to update role")
		return nil, repoError(span, err, "role", "update")
	}

	audit.Log("Role", "RoleUpdated", "", role.ID, role.Name, true, nil)
	return connect.NewResponse(&ssov1.UpdateRoleResponse{Role: toRoleProto(role)}), nil
}

// DeleteRole removes a role.
func (s *RoleServiceServer) DeleteRole(ctx context.Context, req *connect.Request[ssov1.DeleteRoleRequest]) (*connect.Response[emptypb.Empty], error) {
	ctx, span := telemetry.StartSpan(ctx, roleServiceTracerName, "DeleteRole",
		attribute.String("role.id", req.Msg.GetId()))
	defer span.End()

	if err := s.roleRepo.DeleteRole(ctx, req.Msg.GetId()); err != nil {
		telemetry.RecordSpanError(span, err, "failed to delete role")
		return nil, repoError(span, err, "role", "delete")
	}

	audit.Log("Role", "RoleDeleted", "", req.Msg.GetId(), "", true, nil)
	return connect.NewResponse(&emptypb.Empty{}), nil
}

// CreateCompositeRole creates a composite role and attaches its child roles.
func (s *RoleServiceServer) CreateCompositeRole(ctx context.Context, req *connect.Request[ssov1.CreateCompositeRoleRequest]) (*connect.Response[ssov1.CreateCompositeRoleResponse], error) {
	ctx, span := telemetry.StartSpan(ctx, roleServiceTracerName, "CreateCompositeRole",
		attribute.String("role.name", req.Msg.GetName()))
	defer span.End()

	if strings.TrimSpace(req.Msg.GetName()) == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("name is required"))
	}

	role := &domain.Role{
		Name:        req.Msg.GetName(),
		Description: req.Msg.GetDescription(),
		Composite:   true,
	}
	if err := s.roleRepo.CreateRole(ctx, role); err != nil {
		telemetry.RecordSpanError(span, err, "failed to create composite role")
		return nil, repoError(span, err, "role", "create")
	}

	children := append([]string(nil), req.Msg.GetRealmRoleIds()...)
	for _, ref := range req.Msg.GetClientRoles() {
		children = append(children, ref.GetRoleId())
	}
	for _, childID := range children {
		if err := s.roleRepo.AddChildRole(ctx, role.ID, childID); err != nil {
			telemetry.RecordSpanError(span, err, "failed to add child role")
			return nil, repoError(span, err, "child role", "add")
		}
		role.ChildRoles = append(role.ChildRoles, childID)
	}

	audit.Log("Role", "CompositeRoleCreated", "", role.ID, role.Name, true, nil)
	return connect.NewResponse(&ssov1.CreateCompositeRoleResponse{Role: toRoleProto(role)}), nil
}

// GetUserRoleMappings returns the realm and client roles assigned to a user.
func (s *RoleServiceServer) GetUserRoleMappings(ctx context.Context, req *connect.Request[ssov1.GetUserRoleMappingsRequest]) (*connect.Response[ssov1.GetUserRoleMappingsResponse], error) {
	ctx, span := telemetry.StartSpan(ctx, roleServiceTracerName, "GetUserRoleMappings",
		attribute.String("user.id", req.Msg.GetUserId()))
	defer span.End()

	user, err := s.loadUser(ctx, req.Msg.GetUserId())
	if err != nil {
		telemetry.RecordSpanError(span, err, "failed to load user")
		return nil, err
	}
	clientMappings := make([]*domain.Role, 0)
	for _, names := range user.ClientRoles {
		clientMappings = append(clientMappings, resolveRoleNames(ctx, s.roleRepo, names)...)
	}
	return connect.NewResponse(&ssov1.GetUserRoleMappingsResponse{
		RealmMappings:  toRoleProtos(resolveRoleNames(ctx, s.roleRepo, user.Roles)),
		ClientMappings: toRoleProtos(clientMappings),
	}), nil
}

// GetUserClientRoleMappings returns the roles a user holds for one client.
func (s *RoleServiceServer) GetUserClientRoleMappings(ctx context.Context, req *connect.Request[ssov1.GetUserClientRoleMappingsRequest]) (*connect.Response[ssov1.GetUserClientRoleMappingsResponse], error) {
	ctx, span := telemetry.StartSpan(ctx, roleServiceTracerName, "GetUserClientRoleMappings",
		attribute.String("user.id", req.Msg.GetUserId()),
		attribute.String("client.id", req.Msg.GetClientId()))
	defer span.End()

	user, err := s.loadUser(ctx, req.Msg.GetUserId())
	if err != nil {
		telemetry.RecordSpanError(span, err, "failed to load user")
		return nil, err
	}
	roles := resolveRoleNames(ctx, s.roleRepo, user.ClientRoles[req.Msg.GetClientId()])
	return connect.NewResponse(&ssov1.GetUserClientRoleMappingsResponse{Roles: toRoleProtos(roles)}), nil
}

// AddRealmRoleToUser assigns a realm role to a user.
func (s *RoleServiceServer) AddRealmRoleToUser(ctx context.Context, req *connect.Request[ssov1.AddRealmRoleToUserRequest]) (*connect.Response[emptypb.Empty], error) {
	ctx, span := telemetry.StartSpan(ctx, roleServiceTracerName, "AddRealmRoleToUser",
		attribute.String("user.id", req.Msg.GetUserId()), attribute.String("role.id", req.Msg.GetRoleId()))
	defer span.End()

	return s.mutateUserRole(ctx, span, "RealmRoleAddedToUser", req.Msg.GetUserId(), req.Msg.GetRoleId(),
		func(user *domain.User, role *domain.Role) bool {
			if containsRoleName(user.Roles, role.Name) {
				return false
			}
			user.Roles = append(user.Roles, role.Name)
			return true
		})
}

// RemoveRealmRoleFromUser unassigns a realm role from a user.
func (s *RoleServiceServer) RemoveRealmRoleFromUser(ctx context.Context, req *connect.Request[ssov1.RemoveRealmRoleFromUserRequest]) (*connect.Response[emptypb.Empty], error) {
	ctx, span := telemetry.StartSpan(ctx, roleServiceTracerName, "RemoveRealmRoleFromUser",
		attribute.String("user.id", req.Msg.GetUserId()), attribute.String("role.id", req.Msg.GetRoleId()))
	defer span.End()

	return s.mutateUserRole(ctx, span, "RealmRoleRemovedFromUser", req.Msg.GetUserId(), req.Msg.GetRoleId(),
		func(user *domain.User, role *domain.Role) bool {
			var changed bool
			user.Roles, changed = removeRoleName(user.Roles, role.Name)
			return changed
		})
}

// AddClientRoleToUser assigns a client role to a user.
func (s *RoleServiceServer) AddClientRoleToUser(ctx context.Context, req *connect.Request[ssov1.AddClientRoleToUserRequest]) (*connect.Response[emptypb.Empty], error) {
	ctx, span := telemetry.StartSpan(ctx, roleServiceTracerName, "AddClientRoleToUser",
		attribute.String("user.id", req.Msg.GetUserId()), attribute.String("client.id", req.Msg.GetClientId()),
		attribute.String("role.id", req.Msg.GetRoleId()))
	defer span.End()

	clientID := req.Msg.GetClientId()
	return s.mutateUserRole(ctx, span, "ClientRoleAddedToUser", req.Msg.GetUserId(), req.Msg.GetRoleId(),
		func(user *domain.User, role *domain.Role) bool {
			if user.ClientRoles == nil {
				user.ClientRoles = make(map[string][]string)
			}
			if containsRoleName(user.ClientRoles[clientID], role.Name) {
				return false
			}
			user.ClientRoles[clientID] = append(user.ClientRoles[clientID], role.Name)
			return true
		})
}

// RemoveClientRoleFromUser unassigns a client role from a user.
func (s *RoleServiceServer) RemoveClientRoleFromUser(ctx context.Context, req *connect.Request[ssov1.RemoveClientRoleFromUserRequest]) (*connect.Response[emptypb.Empty], error) {
	ctx, span := telemetry.StartSpan(ctx, roleServiceTracerName, "RemoveClientRoleFromUser",
		attribute.String("user.id", req.Msg.GetUserId()), attribute.String("client.id", req.Msg.GetClientId()),
		attribute.String("role.id", req.Msg.GetRoleId()))
	defer span.End()

	clientID := req.Msg.GetClientId()
	return s.mutateUserRole(ctx, span, "ClientRoleRemovedFromUser", req.Msg.GetUserId(), req.Msg.GetRoleId(),
		func(user *domain.User, role *domain.Role) bool {
			remaining, changed := removeRoleName(user.ClientRoles[clientID], role.Name)
			if changed {
				user.ClientRoles[clientID] = remaining
			}
			return changed
		})
}

// mutateUserRole loads role+user, applies mutate and persists when it reports a change.
func (s *RoleServiceServer) mutateUserRole(ctx context.Context, span interface {
	SetStatus(codes.Code, string)
}, event, userID, roleID string, mutate func(*domain.User, *domain.Role) bool) (*connect.Response[emptypb.Empty], error) {
	role, err := s.roleRepo.GetRoleByID(ctx, roleID)
	if err != nil {
		return nil, repoError(span, err, "role", "retrieve")
	}
	if role == nil {
		return nil, connect.NewError(connect.CodeNotFound, errors.New("role not found"))
	}
	user, err := s.loadUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	if mutate(user, role) {
		if err := s.userRepo.UpdateUser(ctx, user); err != nil {
			return nil, repoError(span, err, "user", "update")
		}
	}

	audit.Log("Role", event, userID, roleID, role.Name, true, nil)
	return connect.NewResponse(&emptypb.Empty{}), nil
}

func (s *RoleServiceServer) loadUser(ctx context.Context, userID string) (*domain.User, error) {
	user, err := s.userRepo.GetUserByID(ctx, userID)
	if err != nil {
		if isNotFoundError(err) {
			return nil, connect.NewError(connect.CodeNotFound, errors.New("user not found"))
		}
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to retrieve user"))
	}
	if user == nil {
		return nil, connect.NewError(connect.CodeNotFound, errors.New("user not found"))
	}
	return user, nil
}

// resolveRoleNames resolves role names stored on users into role documents,
// skipping names that cannot be resolved.
func resolveRoleNames(ctx context.Context, repo domain.RoleRepository, names []string) []*domain.Role {
	roles := make([]*domain.Role, 0, len(names))
	for _, name := range names {
		if name == "" {
			continue
		}
		role, err := repo.GetRoleByName(ctx, name)
		if err != nil || role == nil {
			continue
		}
		roles = append(roles, role)
	}
	return roles
}

func containsRoleName(list []string, v string) bool {
	for _, item := range list {
		if item == v {
			return true
		}
	}
	return false
}

func removeRoleName(list []string, v string) ([]string, bool) {
	for i, item := range list {
		if item == v {
			return append(list[:i:i], list[i+1:]...), true
		}
	}
	return list, false
}

func toRoleProtos(roles []*domain.Role) []*ssov1.Role {
	out := make([]*ssov1.Role, 0, len(roles))
	for _, r := range roles {
		if r != nil {
			out = append(out, toRoleProto(r))
		}
	}
	return out
}

func toRoleProto(role *domain.Role) *ssov1.Role {
	if role == nil {
		return nil
	}
	out := &ssov1.Role{
		Id:           role.ID,
		Name:         role.Name,
		Description:  role.Description,
		Composite:    role.Composite,
		ClientRole:   role.ClientRole,
		ContainerId:  role.ContainerID,
		ChildRoleIds: role.ChildRoles,
	}
	if !role.CreatedAt.IsZero() {
		out.CreatedAt = timestamppb.New(role.CreatedAt)
	}
	if !role.UpdatedAt.IsZero() {
		out.UpdatedAt = timestamppb.New(role.UpdatedAt)
	}
	return out
}
