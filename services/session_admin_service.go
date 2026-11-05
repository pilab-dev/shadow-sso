package services

import (
	"context"
	"errors"
	"sort"
	"time"

	"connectrpc.com/connect"
	"github.com/pilab-dev/shadow-sso/domain"
	ssov1 "github.com/pilab-dev/shadow-sso/gen/proto/sso/v1"
	"github.com/pilab-dev/shadow-sso/gen/proto/sso/v1/ssov1connect"
	"github.com/pilab-dev/shadow-sso/internal/audit"
	"github.com/pilab-dev/shadow-sso/internal/telemetry"
	"github.com/rs/zerolog/log"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	sessionAdminTracerName       = "session-admin-service"
	sessionAdminDefaultEventsMax = 50
)

// SessionAdminServiceServer implements ssov1.SessionAdminService.
type SessionAdminServiceServer struct {
	ssov1connect.UnimplementedSessionAdminServiceHandler
	sessionRepo domain.SessionRepository
	tokenRepo   domain.TokenRepository // optional; when set, tokens of revoked sessions are revoked too
}

// NewSessionAdminServer creates the session admin service. tokenRepo may be nil.
func NewSessionAdminServer(sessionRepo domain.SessionRepository, tokenRepo domain.TokenRepository) *SessionAdminServiceServer {
	return &SessionAdminServiceServer{sessionRepo: sessionRepo, tokenRepo: tokenRepo}
}

var _ ssov1connect.SessionAdminServiceHandler = (*SessionAdminServiceServer)(nil)

func (s *SessionAdminServiceServer) fail(span interface {
	SetStatus(codes.Code, string)
}, err error, msg string,
) error {
	span.SetStatus(codes.Error, msg)
	if isNotFoundError(err) || errors.Is(err, domain.ErrSessionNotFound) {
		return connect.NewError(connect.CodeNotFound, errors.New("session not found"))
	}
	return connect.NewError(connect.CodeInternal, errors.New(msg))
}

// ListSessions lists sessions, optionally filtered by user and client.
func (s *SessionAdminServiceServer) ListSessions(ctx context.Context, req *connect.Request[ssov1.ListSessionsRequest]) (*connect.Response[ssov1.ListSessionsResponse], error) {
	ctx, span := telemetry.StartSpan(ctx, sessionAdminTracerName, "ListSessions",
		attribute.String("user.id", req.Msg.GetUserId()),
		attribute.String("client.id", req.Msg.GetClientId()))
	defer span.End()

	filter := domain.SessionFilter{UserID: req.Msg.GetUserId(), ClientID: req.Msg.GetClientId()}
	sessions, err := s.sessionRepo.ListSessionsByUserID(ctx, filter.UserID, filter)
	if err != nil {
		telemetry.RecordSpanError(span, err, "failed to list sessions")
		return nil, s.fail(span, err, "failed to list sessions")
	}
	sessions = filterSessionsByClient(sessions, filter.ClientID)

	page, next := paginate(sessions, pageOffsetFromToken(req.Msg.GetPageToken()), normalizePageSize(req.Msg.GetPageSize()))
	return connect.NewResponse(&ssov1.ListSessionsResponse{
		Sessions:      toAdminSessionProtos(ctx, page),
		NextPageToken: next,
		TotalCount:    int32(len(sessions)),
	}), nil
}

// GetSession returns one session.
func (s *SessionAdminServiceServer) GetSession(ctx context.Context, req *connect.Request[ssov1.GetSessionRequest]) (*connect.Response[ssov1.GetSessionResponse], error) {
	ctx, span := telemetry.StartSpan(ctx, sessionAdminTracerName, "GetSession",
		attribute.String("session.id", req.Msg.GetId()))
	defer span.End()

	session, err := s.sessionRepo.GetSessionByID(ctx, req.Msg.GetId())
	if err != nil {
		telemetry.RecordSpanError(span, err, "failed to get session")
		return nil, s.fail(span, err, "failed to retrieve session")
	}
	return connect.NewResponse(&ssov1.GetSessionResponse{Session: toAdminSessionProto(ctx, session)}), nil
}

// ListSessionEvents returns the lifecycle event log of a session.
func (s *SessionAdminServiceServer) ListSessionEvents(ctx context.Context, req *connect.Request[ssov1.ListSessionEventsRequest]) (*connect.Response[ssov1.ListSessionEventsResponse], error) {
	ctx, span := telemetry.StartSpan(ctx, sessionAdminTracerName, "ListSessionEvents",
		attribute.String("session.id", req.Msg.GetSessionId()))
	defer span.End()

	if _, err := s.sessionRepo.GetSessionByID(ctx, req.Msg.GetSessionId()); err != nil {
		telemetry.RecordSpanError(span, err, "failed to get session")
		return nil, s.fail(span, err, "failed to retrieve session")
	}
	limit := sessionAdminDefaultEventsMax
	if req.Msg.GetLimit() > 0 {
		limit = int(req.Msg.GetLimit())
	}
	events, err := s.sessionRepo.ListSessionEvents(ctx, req.Msg.GetSessionId(), limit)
	if err != nil {
		telemetry.RecordSpanError(span, err, "failed to list session events")
		return nil, s.fail(span, err, "failed to list session events")
	}
	out := make([]*ssov1.AdminSessionEvent, 0, len(events))
	for _, e := range events {
		out = append(out, &ssov1.AdminSessionEvent{
			Id:        e.ID,
			SessionId: e.SessionID,
			UserId:    e.UserID,
			ClientId:  e.ClientID,
			Type:      e.Type,
			IpAddress: e.IPAddress,
			Geo:       e.Geo,
			UserAgent: e.UserAgent,
			At:        timestamppb.New(e.At),
			Actor:     e.Actor,
			Reason:    e.Reason,
		})
	}
	return connect.NewResponse(&ssov1.ListSessionEventsResponse{Events: out}), nil
}

// ListUserSessions lists all sessions of a user.
func (s *SessionAdminServiceServer) ListUserSessions(ctx context.Context, req *connect.Request[ssov1.ListAdminUserSessionsRequest]) (*connect.Response[ssov1.ListAdminUserSessionsResponse], error) {
	ctx, span := telemetry.StartSpan(ctx, sessionAdminTracerName, "ListUserSessions",
		attribute.String("user.id", req.Msg.GetUserId()))
	defer span.End()

	sessions, err := s.sessionRepo.ListSessionsByUserID(ctx, req.Msg.GetUserId(), domain.SessionFilter{})
	if err != nil {
		telemetry.RecordSpanError(span, err, "failed to list user sessions")
		return nil, s.fail(span, err, "failed to list user sessions")
	}
	return connect.NewResponse(&ssov1.ListAdminUserSessionsResponse{Sessions: toAdminSessionProtos(ctx, sessions)}), nil
}

// ListClientUserSessions lists a user's sessions created by one client.
func (s *SessionAdminServiceServer) ListClientUserSessions(ctx context.Context, req *connect.Request[ssov1.ListClientUserSessionsRequest]) (*connect.Response[ssov1.ListClientUserSessionsResponse], error) {
	ctx, span := telemetry.StartSpan(ctx, sessionAdminTracerName, "ListClientUserSessions",
		attribute.String("user.id", req.Msg.GetUserId()),
		attribute.String("client.id", req.Msg.GetClientId()))
	defer span.End()

	sessions, err := s.sessionRepo.ListSessionsByUserID(ctx, req.Msg.GetUserId(),
		domain.SessionFilter{UserID: req.Msg.GetUserId(), ClientID: req.Msg.GetClientId()})
	if err != nil {
		telemetry.RecordSpanError(span, err, "failed to list client user sessions")
		return nil, s.fail(span, err, "failed to list client user sessions")
	}
	sessions = filterSessionsByClient(sessions, req.Msg.GetClientId())
	return connect.NewResponse(&ssov1.ListClientUserSessionsResponse{Sessions: toAdminSessionProtos(ctx, sessions)}), nil
}

// RevokeSession revokes a single session and the tokens issued for it.
func (s *SessionAdminServiceServer) RevokeSession(ctx context.Context, req *connect.Request[ssov1.RevokeSessionRequest]) (*connect.Response[ssov1.RevokeSessionResponse], error) {
	ctx, span := telemetry.StartSpan(ctx, sessionAdminTracerName, "RevokeSession",
		attribute.String("session.id", req.Msg.GetSessionId()))
	defer span.End()

	session, err := s.sessionRepo.GetSessionByID(ctx, req.Msg.GetSessionId())
	if err != nil {
		telemetry.RecordSpanError(span, err, "failed to get session")
		return nil, s.fail(span, err, "failed to retrieve session")
	}
	if err := s.revoke(ctx, session, "revokeSession"); err != nil {
		telemetry.RecordSpanError(span, err, "failed to revoke session")
		audit.Log("Session", "SessionRevoked", sessionAdminActor(ctx), session.ID, "", false, err)
		return nil, s.fail(span, err, "failed to revoke session")
	}
	audit.Log("Session", "SessionRevoked", sessionAdminActor(ctx), session.ID, session.UserID, true, nil)
	return connect.NewResponse(&ssov1.RevokeSessionResponse{Success: true}), nil
}

// RevokeOtherSessions revokes all of a user's sessions except the kept one.
func (s *SessionAdminServiceServer) RevokeOtherSessions(ctx context.Context, req *connect.Request[ssov1.RevokeOtherSessionsRequest]) (*connect.Response[ssov1.RevokeOtherSessionsResponse], error) {
	ctx, span := telemetry.StartSpan(ctx, sessionAdminTracerName, "RevokeOtherSessions",
		attribute.String("user.id", req.Msg.GetUserId()))
	defer span.End()

	keep := ""
	if req.Msg.ExceptSessionId != nil {
		keep = req.Msg.GetExceptSessionId()
	} else if info, ok := domain.GetAuthenticatedTokenFromContext(ctx); ok && info != nil {
		keep = info.SessionID
	}

	sessions, err := s.sessionRepo.ListSessionsByUserID(ctx, req.Msg.GetUserId(), domain.SessionFilter{})
	if err != nil {
		telemetry.RecordSpanError(span, err, "failed to list sessions")
		return nil, s.fail(span, err, "failed to list user sessions")
	}
	revoked := 0
	for _, sess := range sessions {
		if sess.ID == keep {
			continue
		}
		if err := s.revoke(ctx, sess, "revokeOtherSessions"); err != nil {
			telemetry.RecordSpanError(span, err, "failed to revoke session")
			audit.Log("Session", "OtherSessionsRevoked", sessionAdminActor(ctx), req.Msg.GetUserId(), "", false, err)
			return nil, s.fail(span, err, "failed to revoke session")
		}
		revoked++
	}
	audit.Log("Session", "OtherSessionsRevoked", sessionAdminActor(ctx), req.Msg.GetUserId(), "", true, nil)
	return connect.NewResponse(&ssov1.RevokeOtherSessionsResponse{RevokedCount: int32(revoked)}), nil
}

// RevokeAllSessions deletes every session of a user and revokes their tokens.
func (s *SessionAdminServiceServer) RevokeAllSessions(ctx context.Context, req *connect.Request[ssov1.RevokeAllSessionsRequest]) (*connect.Response[ssov1.RevokeAllSessionsResponse], error) {
	ctx, span := telemetry.StartSpan(ctx, sessionAdminTracerName, "RevokeAllSessions",
		attribute.String("user.id", req.Msg.GetUserId()))
	defer span.End()

	if err := s.deleteAll(ctx, req.Msg.GetUserId()); err != nil {
		telemetry.RecordSpanError(span, err, "failed to revoke all sessions")
		audit.Log("Session", "AllSessionsRevoked", sessionAdminActor(ctx), req.Msg.GetUserId(), "", false, err)
		return nil, s.fail(span, err, "failed to revoke sessions")
	}
	audit.Log("Session", "AllSessionsRevoked", sessionAdminActor(ctx), req.Msg.GetUserId(), "", true, nil)
	return connect.NewResponse(&ssov1.RevokeAllSessionsResponse{Success: true}), nil
}

// LogoutUser terminates every session of a user.
func (s *SessionAdminServiceServer) LogoutUser(ctx context.Context, req *connect.Request[ssov1.LogoutUserRequest]) (*connect.Response[ssov1.LogoutUserResponse], error) {
	ctx, span := telemetry.StartSpan(ctx, sessionAdminTracerName, "LogoutUser",
		attribute.String("user.id", req.Msg.GetUserId()))
	defer span.End()

	if err := s.deleteAll(ctx, req.Msg.GetUserId()); err != nil {
		telemetry.RecordSpanError(span, err, "failed to log out user")
		audit.Log("Session", "UserLoggedOut", sessionAdminActor(ctx), req.Msg.GetUserId(), "", false, err)
		return nil, s.fail(span, err, "failed to log out user")
	}
	audit.Log("Session", "UserLoggedOut", sessionAdminActor(ctx), req.Msg.GetUserId(), "", true, nil)
	return connect.NewResponse(&ssov1.LogoutUserResponse{Success: true}), nil
}

// revoke marks a session revoked, revokes its tokens and records an event.
func (s *SessionAdminServiceServer) revoke(ctx context.Context, sess *domain.Session, reason string) error {
	now := time.Now().UTC()
	sess.IsRevoked = true
	sess.RevokedAt = &now
	sess.RevokedBy = "admin"
	sess.RevokeReason = reason
	if err := s.sessionRepo.UpdateSession(ctx, sess); err != nil {
		return err
	}
	if s.tokenRepo != nil {
		if err := s.tokenRepo.RevokeTokensBySessionID(ctx, sess.ID); err != nil {
			return err
		}
	}
	if err := s.sessionRepo.StoreSessionEvent(ctx, &domain.SessionEvent{
		SessionID: sess.ID,
		UserID:    sess.UserID,
		ClientID:  sess.ClientID,
		Type:      "revoked",
		At:        now,
		Actor:     sessionAdminActor(ctx),
		Reason:    reason,
	}); err != nil {
		log.Ctx(ctx).Warn().Err(err).Str("sessionID", sess.ID).Msg("Failed to store session revoke event")
	}
	return nil
}

func (s *SessionAdminServiceServer) deleteAll(ctx context.Context, userID string) error {
	sessions, err := s.sessionRepo.ListSessionsByUserID(ctx, userID, domain.SessionFilter{})
	if err != nil {
		return err
	}
	if _, err := s.sessionRepo.DeleteSessionsByUserID(ctx, userID); err != nil {
		return err
	}
	if s.tokenRepo != nil {
		for _, sess := range sessions {
			if err := s.tokenRepo.RevokeTokensBySessionID(ctx, sess.ID); err != nil {
				return err
			}
		}
	}
	return nil
}

func sessionAdminActor(ctx context.Context) string {
	if info, ok := domain.GetAuthenticatedTokenFromContext(ctx); ok && info != nil {
		return info.UserID
	}
	return ""
}

func filterSessionsByClient(sessions []*domain.Session, clientID string) []*domain.Session {
	if clientID == "" {
		return sessions
	}
	out := make([]*domain.Session, 0, len(sessions))
	for _, sess := range sessions {
		if sess.ClientID == clientID {
			out = append(out, sess)
		}
	}
	return out
}

func toAdminSessionProtos(ctx context.Context, sessions []*domain.Session) []*ssov1.AdminSession {
	sorted := make([]*domain.Session, len(sessions))
	copy(sorted, sessions)
	sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].CreatedAt.After(sorted[j].CreatedAt) })
	out := make([]*ssov1.AdminSession, len(sorted))
	for i, sess := range sorted {
		out[i] = toAdminSessionProto(ctx, sess)
	}
	return out
}

func toAdminSessionProto(ctx context.Context, sess *domain.Session) *ssov1.AdminSession {
	if sess == nil {
		return nil
	}
	state := "active"
	switch {
	case sess.IsRevoked:
		state = "revoked"
	case !sess.ExpiresAt.IsZero() && time.Now().After(sess.ExpiresAt):
		state = "expired"
	}
	lastAccessed := sess.LastSeenAt
	if lastAccessed.IsZero() {
		lastAccessed = sess.LastUsedAt
	}
	out := &ssov1.AdminSession{
		Id:               sess.ID,
		UserId:           sess.UserID,
		ClientId:         sess.ClientID,
		IpAddress:        sess.IPAddress,
		UserAgent:        sess.UserAgent,
		CreatedTime:      timestamppb.New(sess.CreatedAt),
		LastAccessedTime: timestamppb.New(lastAccessed),
		Expires:          timestamppb.New(sess.ExpiresAt),
		State:            state,
		DeviceName:       sess.DeviceName,
		DeviceType:       sess.DeviceType,
		Os:               sess.OS,
		Browser:          sess.Browser,
		IpCountry:        sess.IPCountry,
		IpRegion:         sess.IPRegion,
		IpCity:           sess.IPCity,
		RiskFlags:        sess.RiskFlags,
		RevokeReason:     sess.RevokeReason,
	}
	if sess.RevokedAt != nil {
		out.RevokedAt = timestamppb.New(*sess.RevokedAt)
	}
	if info, ok := domain.GetAuthenticatedTokenFromContext(ctx); ok && info != nil {
		out.Current = (info.SessionID != "" && info.SessionID == sess.ID) || (info.ID != "" && info.ID == sess.TokenID)
	}
	return out
}
