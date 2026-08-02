package services

import (
	"context"
	"fmt"

	"connectrpc.com/connect"
	"github.com/pilab-dev/shadow-sso/domain"
	ssov1 "github.com/pilab-dev/shadow-sso/gen/proto/sso/v1"
	"github.com/pilab-dev/shadow-sso/gen/proto/sso/v1/ssov1connect"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// AuditServer implements the ssov1connect.AuditServiceHandler interface.
type AuditServer struct {
	ssov1connect.UnimplementedAuditServiceHandler
	auditRepo domain.AuditLogRepository
}

// NewAuditServer creates a new AuditServer.
func NewAuditServer(auditRepo domain.AuditLogRepository) *AuditServer {
	return &AuditServer{
		auditRepo: auditRepo,
	}
}

// ListAuditEvents returns persisted audit events filtered by user/action/time
// with pagination. Authorization is enforced by the RBAC interceptor
// (PermAuditRead), so a non-admin caller never reaches this method.
func (s *AuditServer) ListAuditEvents(ctx context.Context, req *connect.Request[ssov1.ListAuditEventsRequest]) (*connect.Response[ssov1.ListAuditEventsResponse], error) {
	filter := domain.AuditLogFilter{
		User:   req.Msg.GetUser(),
		Action: req.Msg.GetAction(),
	}
	if t := req.Msg.GetFrom(); t != nil {
		ts := t.AsTime()
		filter.From = &ts
	}
	if t := req.Msg.GetTo(); t != nil {
		ts := t.AsTime()
		filter.To = &ts
	}

	limit := int(req.Msg.GetLimit())
	if limit <= 0 || limit > 500 {
		limit = 50
	}
	offset := int(req.Msg.GetOffset())
	if offset < 0 {
		offset = 0
	}

	events, err := s.auditRepo.List(ctx, filter, limit, offset)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to list audit events: %w", err))
	}
	total, err := s.auditRepo.Count(ctx, filter)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to count audit events: %w", err))
	}

	resp := &ssov1.ListAuditEventsResponse{
		Total:  total,
		Limit:  int32(limit),
		Offset: int32(offset),
		Events: make([]*ssov1.AuditEventProto, 0, len(events)),
	}
	for _, e := range events {
		if e == nil {
			continue
		}
		resp.Events = append(resp.Events, toAuditEventProto(e))
	}
	return connect.NewResponse(resp), nil
}

func toAuditEventProto(e *domain.AuditLog) *ssov1.AuditEventProto {
	return &ssov1.AuditEventProto{
		Id:        e.ID,
		Timestamp: timestamppb.New(e.Timestamp),
		Service:   e.Service,
		Action:    e.Action,
		User:      e.User,
		Target:    e.Target,
		Details:   e.Details,
		Success:   e.Success,
		Error:     e.Error,
	}
}
