package services

import (
	"context"
	"fmt"
	"time"

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

// FollowAuditEvents streams audit events oldest-first, optionally replaying
// existing events first. It polls the audit store instead of subscribing to an
// in-process bus, so a follower sees events written by every server replica.
func (s *AuditServer) FollowAuditEvents(
	ctx context.Context,
	req *connect.Request[ssov1.FollowAuditEventsRequest],
	stream *connect.ServerStream[ssov1.AuditEventProto],
) error {
	interval := time.Duration(req.Msg.GetPollIntervalMs()) * time.Millisecond
	if interval < 250*time.Millisecond {
		interval = time.Second
	}
	if interval > 30*time.Second {
		interval = 30 * time.Second
	}
	batch := int(req.Msg.GetBatchSize())
	if batch <= 0 || batch > 1000 {
		batch = 200
	}

	cursor := time.Now().UTC()
	if from := req.Msg.GetFrom(); from != nil {
		cursor = from.AsTime().UTC()
	} else if req.Msg.GetIncludeExisting() {
		// A sensible tail for `-f` without an explicit --since.
		cursor = time.Now().UTC().Add(-time.Hour)
	}

	filter := domain.AuditLogFilter{
		User:   req.Msg.GetUser(),
		Action: req.Msg.GetAction(),
	}

	// Events at the cursor timestamp are returned again by the inclusive
	// ListAfter query. Track their IDs so each event is emitted once.
	seen := make(map[string]struct{})
	for {
		events, err := s.auditRepo.ListAfter(ctx, filter, cursor, batch)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return connect.NewError(connect.CodeInternal, fmt.Errorf("failed to read audit events: %w", err))
		}

		sent := 0
		for _, e := range events {
			if e == nil {
				continue
			}
			key := eventKey(e)
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			if err := stream.Send(toAuditEventProto(e)); err != nil {
				if ctx.Err() != nil {
					return nil
				}
				return err
			}
			sent++
		}

		if len(events) > 0 {
			last := events[len(events)-1]
			if last.Timestamp.After(cursor) {
				cursor = last.Timestamp
				// Keep only events at the new cursor timestamp: the inclusive
				// query will return them again on the next poll, and they must
				// not be emitted twice.
				seen = seenAt(events, cursor)
			} else if len(events) >= batch {
				// A full batch at the same timestamp: advance by the smallest
				// amount so the next query makes progress. Nanosecond audit
				// timestamps make a real collision vanishingly unlikely.
				cursor = cursor.Add(time.Nanosecond)
				seen = make(map[string]struct{})
			}
		}
		if sent > 0 {
			// New events are available right now; do not wait a full poll
			// interval before checking again.
			continue
		}

		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil
		case <-timer.C:
		}
	}
}

func eventKey(e *domain.AuditLog) string {
	if e.ID != "" {
		return e.ID
	}
	return e.Timestamp.UTC().String() + "|" + e.Service + "|" + e.Action + "|" + e.Target
}

func seenAt(events []*domain.AuditLog, ts time.Time) map[string]struct{} {
	seen := make(map[string]struct{})
	for _, e := range events {
		if e != nil && e.Timestamp.Equal(ts) {
			seen[eventKey(e)] = struct{}{}
		}
	}
	return seen
}
