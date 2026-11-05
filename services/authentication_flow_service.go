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
	"github.com/rs/zerolog/log"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const authFlowServiceTracerName = "authentication-flow-service"

// AuthenticationFlowServiceServer implements ssov1.AuthenticationFlowService.
type AuthenticationFlowServiceServer struct {
	ssov1connect.UnimplementedAuthenticationFlowServiceHandler
	flowRepo domain.AuthenticationFlowRepository
}

// NewAuthenticationFlowServer creates the authentication flow admin service.
func NewAuthenticationFlowServer(flowRepo domain.AuthenticationFlowRepository) *AuthenticationFlowServiceServer {
	return &AuthenticationFlowServiceServer{flowRepo: flowRepo}
}

var _ ssov1connect.AuthenticationFlowServiceHandler = (*AuthenticationFlowServiceServer)(nil)

func (s *AuthenticationFlowServiceServer) repoError(span interface {
	SetStatus(codes.Code, string)
}, err error, what string) error {
	span.SetStatus(codes.Error, what)
	if isNotFoundError(err) {
		return connect.NewError(connect.CodeNotFound, errors.New("authentication flow not found"))
	}
	return connect.NewError(connect.CodeInternal, errors.New(what))
}

// ListAuthenticationFlows lists all flows.
func (s *AuthenticationFlowServiceServer) ListAuthenticationFlows(ctx context.Context, _ *connect.Request[ssov1.ListAuthenticationFlowsRequest]) (*connect.Response[ssov1.ListAuthenticationFlowsResponse], error) {
	ctx, span := telemetry.StartSpan(ctx, authFlowServiceTracerName, "ListAuthenticationFlows")
	defer span.End()

	flows, err := s.flowRepo.ListFlows(ctx)
	if err != nil {
		telemetry.RecordSpanError(span, err, "failed to list authentication flows")
		return nil, s.repoError(span, err, "failed to list authentication flows")
	}
	out := make([]*ssov1.AuthenticationFlow, 0, len(flows))
	for _, f := range flows {
		out = append(out, toAuthenticationFlowProto(f))
	}
	return connect.NewResponse(&ssov1.ListAuthenticationFlowsResponse{Flows: out}), nil
}

// ListAuthenticationExecutions lists the executions of a flow.
func (s *AuthenticationFlowServiceServer) ListAuthenticationExecutions(ctx context.Context, req *connect.Request[ssov1.ListAuthenticationExecutionsRequest]) (*connect.Response[ssov1.ListAuthenticationExecutionsResponse], error) {
	ctx, span := telemetry.StartSpan(ctx, authFlowServiceTracerName, "ListAuthenticationExecutions",
		attribute.String("flow.id", req.Msg.GetFlowId()))
	defer span.End()

	if strings.TrimSpace(req.Msg.GetFlowId()) == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("flow_id is required"))
	}
	execs, err := s.flowRepo.GetExecutions(ctx, req.Msg.GetFlowId())
	if err != nil {
		telemetry.RecordSpanError(span, err, "failed to list authentication executions")
		return nil, s.repoError(span, err, "failed to list authentication executions")
	}
	out := make([]*ssov1.AuthenticationExecution, 0, len(execs))
	for _, e := range execs {
		out = append(out, &ssov1.AuthenticationExecution{
			Id:                   e.ID,
			FlowId:               e.FlowID,
			Execution:            e.Execution,
			Authenticator:        e.Authenticator,
			Requirement:          e.Requirement,
			Priority:             int32(e.Priority),
			AuthenticationConfig: e.AuthenticationConfig,
		})
	}
	return connect.NewResponse(&ssov1.ListAuthenticationExecutionsResponse{Executions: out}), nil
}

// CreateAuthenticationFlow creates a flow.
func (s *AuthenticationFlowServiceServer) CreateAuthenticationFlow(ctx context.Context, req *connect.Request[ssov1.CreateAuthenticationFlowRequest]) (*connect.Response[ssov1.CreateAuthenticationFlowResponse], error) {
	ctx, span := telemetry.StartSpan(ctx, authFlowServiceTracerName, "CreateAuthenticationFlow",
		attribute.String("flow.alias", req.Msg.GetAlias()))
	defer span.End()

	if strings.TrimSpace(req.Msg.GetAlias()) == "" || strings.TrimSpace(req.Msg.GetDisplayName()) == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("alias and display_name are required"))
	}
	flow := &domain.AuthenticationFlow{
		Alias:       req.Msg.GetAlias(),
		DisplayName: req.Msg.GetDisplayName(),
		Description: req.Msg.GetDescription(),
		BuiltIn:     req.Msg.GetBuiltIn(),
		TopLevel:    req.Msg.GetTopLevel(),
	}
	if err := s.flowRepo.CreateFlow(ctx, flow); err != nil {
		telemetry.RecordSpanError(span, err, "failed to create authentication flow")
		span.SetStatus(codes.Error, "failed to create authentication flow")
		log.Ctx(ctx).Error().Err(err).Str("alias", flow.Alias).Msg("Failed to create authentication flow")
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to create authentication flow"))
	}
	audit.Log("AuthenticationFlow", "AuthenticationFlowCreated", "", flow.ID, flow.Alias, true, nil)
	return connect.NewResponse(&ssov1.CreateAuthenticationFlowResponse{Flow: toAuthenticationFlowProto(flow)}), nil
}

// UpdateAuthenticationFlow patches a flow.
func (s *AuthenticationFlowServiceServer) UpdateAuthenticationFlow(ctx context.Context, req *connect.Request[ssov1.UpdateAuthenticationFlowRequest]) (*connect.Response[ssov1.UpdateAuthenticationFlowResponse], error) {
	ctx, span := telemetry.StartSpan(ctx, authFlowServiceTracerName, "UpdateAuthenticationFlow",
		attribute.String("flow.id", req.Msg.GetId()))
	defer span.End()

	if strings.TrimSpace(req.Msg.GetId()) == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("id is required"))
	}
	flow, err := s.flowRepo.GetFlowByID(ctx, req.Msg.GetId())
	if err != nil {
		telemetry.RecordSpanError(span, err, "failed to get authentication flow")
		return nil, s.repoError(span, err, "failed to retrieve authentication flow")
	}
	if req.Msg.Alias != nil {
		flow.Alias = req.Msg.GetAlias()
	}
	if req.Msg.DisplayName != nil {
		flow.DisplayName = req.Msg.GetDisplayName()
	}
	if req.Msg.Description != nil {
		flow.Description = req.Msg.GetDescription()
	}
	if err := s.flowRepo.UpdateFlow(ctx, flow); err != nil {
		telemetry.RecordSpanError(span, err, "failed to update authentication flow")
		return nil, s.repoError(span, err, "failed to update authentication flow")
	}
	audit.Log("AuthenticationFlow", "AuthenticationFlowUpdated", "", flow.ID, flow.Alias, true, nil)
	return connect.NewResponse(&ssov1.UpdateAuthenticationFlowResponse{Flow: toAuthenticationFlowProto(flow)}), nil
}

// DeleteAuthenticationFlow deletes a flow.
func (s *AuthenticationFlowServiceServer) DeleteAuthenticationFlow(ctx context.Context, req *connect.Request[ssov1.DeleteAuthenticationFlowRequest]) (*connect.Response[emptypb.Empty], error) {
	ctx, span := telemetry.StartSpan(ctx, authFlowServiceTracerName, "DeleteAuthenticationFlow",
		attribute.String("flow.id", req.Msg.GetId()))
	defer span.End()

	if strings.TrimSpace(req.Msg.GetId()) == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("id is required"))
	}
	if err := s.flowRepo.DeleteFlow(ctx, req.Msg.GetId()); err != nil {
		telemetry.RecordSpanError(span, err, "failed to delete authentication flow")
		return nil, s.repoError(span, err, "failed to delete authentication flow")
	}
	audit.Log("AuthenticationFlow", "AuthenticationFlowDeleted", "", req.Msg.GetId(), "", true, nil)
	return connect.NewResponse(&emptypb.Empty{}), nil
}

// UpdateAuthenticationExecutions upserts the given executions into a flow.
func (s *AuthenticationFlowServiceServer) UpdateAuthenticationExecutions(ctx context.Context, req *connect.Request[ssov1.UpdateAuthenticationExecutionsRequest]) (*connect.Response[emptypb.Empty], error) {
	ctx, span := telemetry.StartSpan(ctx, authFlowServiceTracerName, "UpdateAuthenticationExecutions",
		attribute.String("flow.id", req.Msg.GetFlowId()))
	defer span.End()

	flowID := req.Msg.GetFlowId()
	if strings.TrimSpace(flowID) == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("flow_id is required"))
	}
	for _, in := range req.Msg.GetExecutions() {
		if strings.TrimSpace(in.GetExecution()) == "" || strings.TrimSpace(in.GetRequirement()) == "" {
			return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("execution and requirement are required"))
		}
	}
	if _, err := s.flowRepo.GetFlowByID(ctx, flowID); err != nil {
		telemetry.RecordSpanError(span, err, "failed to get authentication flow")
		return nil, s.repoError(span, err, "failed to retrieve authentication flow")
	}
	for _, in := range req.Msg.GetExecutions() {
		exec := &domain.AuthenticationExecution{
			ID:          in.GetId(),
			FlowID:      flowID,
			Execution:   in.GetExecution(),
			Requirement: in.GetRequirement(),
		}
		if err := s.flowRepo.UpsertExecution(ctx, exec); err != nil {
			telemetry.RecordSpanError(span, err, "failed to upsert authentication execution")
			return nil, s.repoError(span, err, "failed to update authentication executions")
		}
	}
	audit.Log("AuthenticationFlow", "AuthenticationExecutionsUpdated", "", flowID, "", true, nil)
	return connect.NewResponse(&emptypb.Empty{}), nil
}

func toAuthenticationFlowProto(f *domain.AuthenticationFlow) *ssov1.AuthenticationFlow {
	out := &ssov1.AuthenticationFlow{
		Id:          f.ID,
		Alias:       f.Alias,
		DisplayName: f.DisplayName,
		Description: f.Description,
		BuiltIn:     f.BuiltIn,
		TopLevel:    f.TopLevel,
	}
	if !f.CreatedAt.IsZero() {
		out.CreatedAt = timestamppb.New(f.CreatedAt)
	}
	if !f.UpdatedAt.IsZero() {
		out.UpdatedAt = timestamppb.New(f.UpdatedAt)
	}
	return out
}
