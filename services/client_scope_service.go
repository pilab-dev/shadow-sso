package services

import (
	"context"
	"errors"
	"sort"
	"strings"

	"connectrpc.com/connect"
	"github.com/pilab-dev/shadow-sso/domain"
	ssov1 "github.com/pilab-dev/shadow-sso/gen/proto/sso/v1"
	"github.com/pilab-dev/shadow-sso/gen/proto/sso/v1/ssov1connect"
	"github.com/pilab-dev/shadow-sso/internal/audit"
	"github.com/pilab-dev/shadow-sso/internal/telemetry"
	"github.com/rs/zerolog/log"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	clientScopeServiceTracerName = "client-scope-service"
	clientScopeDefaultProtocol   = "openid-connect"
)

// ClientScopeServiceServer implements ssov1.ClientScopeService.
type ClientScopeServiceServer struct {
	ssov1connect.UnimplementedClientScopeServiceHandler
	scopeRepo domain.ClientScopeRepository
}

// NewClientScopeServer creates the client scope admin service.
func NewClientScopeServer(scopeRepo domain.ClientScopeRepository) *ClientScopeServiceServer {
	return &ClientScopeServiceServer{scopeRepo: scopeRepo}
}

var _ ssov1connect.ClientScopeServiceHandler = (*ClientScopeServiceServer)(nil)

// CreateClientScope creates a new client scope.
func (s *ClientScopeServiceServer) CreateClientScope(ctx context.Context, req *connect.Request[ssov1.CreateClientScopeRequest]) (*connect.Response[ssov1.CreateClientScopeResponse], error) {
	ctx, span := telemetry.StartSpan(ctx, clientScopeServiceTracerName, "CreateClientScope",
		attribute.String("scope.name", req.Msg.GetName()))
	defer span.End()

	if strings.TrimSpace(req.Msg.GetName()) == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("name is required"))
	}
	protocol := req.Msg.GetProtocol()
	if strings.TrimSpace(protocol) == "" {
		protocol = clientScopeDefaultProtocol
	}

	scope := &domain.ClientScope{
		Name:              req.Msg.GetName(),
		Description:       req.Msg.GetDescription(),
		Protocol:          protocol,
		ConsentScreenText: req.Msg.GetConsentScreenText(),
	}
	if req.Msg.DisplayOrder != nil {
		scope.DisplayOrder = int(*req.Msg.DisplayOrder)
	}

	if err := s.scopeRepo.CreateClientScope(ctx, scope); err != nil {
		telemetry.RecordSpanError(span, err, "failed to create client scope")
		span.SetStatus(codes.Error, "failed to create client scope")
		log.Ctx(ctx).Error().Err(err).Str("scopeName", scope.Name).Msg("Failed to create client scope")
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to create client scope"))
	}

	audit.Log("ClientScope", "ClientScopeCreated", "", scope.ID, scope.Name, true, nil)
	return connect.NewResponse(&ssov1.CreateClientScopeResponse{ClientScope: toClientScopeProto(scope)}), nil
}

// GetClientScope returns one scope by ID.
func (s *ClientScopeServiceServer) GetClientScope(ctx context.Context, req *connect.Request[ssov1.GetClientScopeRequest]) (*connect.Response[ssov1.GetClientScopeResponse], error) {
	ctx, span := telemetry.StartSpan(ctx, clientScopeServiceTracerName, "GetClientScope",
		attribute.String("scope.id", req.Msg.GetId()))
	defer span.End()

	scope, err := s.scopeRepo.GetClientScopeByID(ctx, req.Msg.GetId())
	if err != nil {
		telemetry.RecordSpanError(span, err, "failed to get client scope")
		span.SetStatus(codes.Error, "failed to retrieve client scope")
		if isNotFoundError(err) {
			return nil, connect.NewError(connect.CodeNotFound, errors.New("client scope not found"))
		}
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to retrieve client scope"))
	}
	return connect.NewResponse(&ssov1.GetClientScopeResponse{ClientScope: toClientScopeProto(scope)}), nil
}

// ListClientScopes lists scopes with optional protocol filtering.
func (s *ClientScopeServiceServer) ListClientScopes(ctx context.Context, req *connect.Request[ssov1.ListClientScopesRequest]) (*connect.Response[ssov1.ListClientScopesResponse], error) {
	ctx, span := telemetry.StartSpan(ctx, clientScopeServiceTracerName, "ListClientScopes",
		attribute.String("scope.protocol", req.Msg.GetProtocol()))
	defer span.End()

	scopes, err := s.scopeRepo.ListClientScopes(ctx)
	if err != nil {
		telemetry.RecordSpanError(span, err, "failed to list client scopes")
		span.SetStatus(codes.Error, "failed to list client scopes")
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to list client scopes"))
	}

	filtered := make([]*domain.ClientScope, 0, len(scopes))
	for _, scope := range scopes {
		if req.Msg.GetProtocol() != "" && scope.Protocol != req.Msg.GetProtocol() {
			continue
		}
		filtered = append(filtered, scope)
	}
	sort.Slice(filtered, func(i, j int) bool {
		if filtered[i].DisplayOrder == filtered[j].DisplayOrder {
			return filtered[i].Name < filtered[j].Name
		}
		return filtered[i].DisplayOrder < filtered[j].DisplayOrder
	})

	page, nextToken := paginate(filtered, pageOffsetFromToken(req.Msg.GetPageToken()), normalizePageSize(req.Msg.GetPageSize()))
	protos := make([]*ssov1.ClientScope, len(page))
	for i, scope := range page {
		protos[i] = toClientScopeProto(scope)
	}

	return connect.NewResponse(&ssov1.ListClientScopesResponse{
		ClientScopes:  protos,
		NextPageToken: nextToken,
	}), nil
}

// UpdateClientScope mutates an existing scope.
func (s *ClientScopeServiceServer) UpdateClientScope(ctx context.Context, req *connect.Request[ssov1.UpdateClientScopeRequest]) (*connect.Response[ssov1.UpdateClientScopeResponse], error) {
	ctx, span := telemetry.StartSpan(ctx, clientScopeServiceTracerName, "UpdateClientScope",
		attribute.String("scope.id", req.Msg.GetId()))
	defer span.End()

	if req.Msg.Name == nil && req.Msg.Description == nil && req.Msg.Protocol == nil &&
		req.Msg.DisplayOrder == nil && req.Msg.ConsentScreenText == nil {
		return nil, connect.NewError(connect.CodeInvalidArgument,
			errors.New("at least one field must be provided for update"))
	}

	scope, err := s.scopeRepo.GetClientScopeByID(ctx, req.Msg.GetId())
	if err != nil {
		telemetry.RecordSpanError(span, err, "failed to retrieve client scope for update")
		span.SetStatus(codes.Error, "client scope not found")
		if isNotFoundError(err) {
			return nil, connect.NewError(connect.CodeNotFound, errors.New("client scope not found"))
		}
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to retrieve client scope"))
	}

	if req.Msg.Name != nil {
		if strings.TrimSpace(*req.Msg.Name) == "" {
			return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("name must not be empty"))
		}
		scope.Name = *req.Msg.Name
	}
	if req.Msg.Description != nil {
		scope.Description = *req.Msg.Description
	}
	if req.Msg.Protocol != nil {
		if strings.TrimSpace(*req.Msg.Protocol) == "" {
			return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("protocol must not be empty"))
		}
		scope.Protocol = *req.Msg.Protocol
	}
	if req.Msg.DisplayOrder != nil {
		scope.DisplayOrder = int(*req.Msg.DisplayOrder)
	}
	if req.Msg.ConsentScreenText != nil {
		scope.ConsentScreenText = *req.Msg.ConsentScreenText
	}

	if err := s.scopeRepo.UpdateClientScope(ctx, scope); err != nil {
		telemetry.RecordSpanError(span, err, "failed to update client scope")
		span.SetStatus(codes.Error, "failed to update client scope")
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to update client scope"))
	}

	audit.Log("ClientScope", "ClientScopeUpdated", "", scope.ID, scope.Name, true, nil)
	return connect.NewResponse(&ssov1.UpdateClientScopeResponse{ClientScope: toClientScopeProto(scope)}), nil
}

// DeleteClientScope removes a scope.
func (s *ClientScopeServiceServer) DeleteClientScope(ctx context.Context, req *connect.Request[ssov1.DeleteClientScopeRequest]) (*connect.Response[emptypb.Empty], error) {
	ctx, span := telemetry.StartSpan(ctx, clientScopeServiceTracerName, "DeleteClientScope",
		attribute.String("scope.id", req.Msg.GetId()))
	defer span.End()

	if err := s.scopeRepo.DeleteClientScope(ctx, req.Msg.GetId()); err != nil {
		telemetry.RecordSpanError(span, err, "failed to delete client scope")
		span.SetStatus(codes.Error, "failed to delete client scope")
		if isNotFoundError(err) {
			return nil, connect.NewError(connect.CodeNotFound, errors.New("client scope not found"))
		}
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to delete client scope"))
	}

	audit.Log("ClientScope", "ClientScopeDeleted", "", req.Msg.GetId(), "", true, nil)
	return connect.NewResponse(&emptypb.Empty{}), nil
}

func toClientScopeProto(scope *domain.ClientScope) *ssov1.ClientScope {
	if scope == nil {
		return nil
	}
	out := &ssov1.ClientScope{
		Id:                scope.ID,
		Name:              scope.Name,
		Description:       scope.Description,
		Protocol:          scope.Protocol,
		DisplayOrder:      int32(scope.DisplayOrder),
		ConsentScreenText: scope.ConsentScreenText,
	}
	if !scope.CreatedAt.IsZero() {
		out.CreatedAt = timestamppb.New(scope.CreatedAt)
	}
	return out
}
