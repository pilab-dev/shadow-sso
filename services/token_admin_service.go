package services

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"connectrpc.com/connect"
	"github.com/pilab-dev/shadow-sso/domain"
	ssov1 "github.com/pilab-dev/shadow-sso/gen/proto/sso/v1"
	"github.com/pilab-dev/shadow-sso/gen/proto/sso/v1/ssov1connect"
	"github.com/pilab-dev/shadow-sso/internal/audit"
	"github.com/pilab-dev/shadow-sso/internal/auth/rbac"
	"github.com/pilab-dev/shadow-sso/internal/browserinfo"
	"github.com/pilab-dev/shadow-sso/internal/reqinfo"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// TokenAdminServer implements the token/device traceability surface.
type TokenAdminServer struct {
	ssov1connect.UnimplementedTokenServiceHandler
	tokenRepo   domain.TokenRepository
	queryRepo   domain.TokenQueryRepository
	sessionRepo domain.SessionRepository
}

// NewTokenAdminServer creates the traceability service. queryRepo may be nil
// when the backing token store does not support listing; read methods then
// return Unimplemented while revocation still works.
func NewTokenAdminServer(tokenRepo domain.TokenRepository, sessionRepo domain.SessionRepository) *TokenAdminServer {
	query, _ := tokenRepo.(domain.TokenQueryRepository)
	return &TokenAdminServer{
		tokenRepo:   tokenRepo,
		queryRepo:   query,
		sessionRepo: sessionRepo,
	}
}

func (s *TokenAdminServer) ListUserTokens(ctx context.Context, req *connect.Request[ssov1.ListUserTokensRequest]) (*connect.Response[ssov1.ListUserTokensResponse], error) {
	targetUserID, err := s.resolveTargetUser(ctx, req.Msg.GetUserId(), rbac.PermSessionsListOthers)
	if err != nil {
		return nil, err
	}
	if s.queryRepo == nil {
		return nil, connect.NewError(connect.CodeUnimplemented,
			errors.New("the configured token store does not support token listing"))
	}

	limit := int(req.Msg.GetLimit())
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	offset := int(req.Msg.GetOffset())
	if offset < 0 {
		offset = 0
	}
	filter := domain.TokenFilter{
		UserID:         targetUserID,
		ClientID:       req.Msg.GetClientId(),
		SessionID:      req.Msg.GetSessionId(),
		TokenType:      req.Msg.GetTokenType(),
		IncludeRevoked: req.Msg.GetIncludeRevoked(),
		IncludeExpired: req.Msg.GetIncludeExpired(),
	}
	tokens, err := s.queryRepo.ListByUserID(ctx, filter, limit, offset)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to list tokens: %w", err))
	}
	total, err := s.queryRepo.CountByUserID(ctx, filter)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to count tokens: %w", err))
	}

	sessions := s.sessionCache(ctx, tokens)
	out := make([]*ssov1.UserToken, 0, len(tokens))
	for _, t := range tokens {
		if t == nil {
			continue
		}
		out = append(out, toUserTokenProto(t, sessions[t.SessionID]))
	}
	return connect.NewResponse(&ssov1.ListUserTokensResponse{
		Tokens: out,
		Total:  total,
		Limit:  int32(limit),
		Offset: int32(offset),
	}), nil
}

func (s *TokenAdminServer) GetToken(ctx context.Context, req *connect.Request[ssov1.GetTokenRequest]) (*connect.Response[ssov1.GetTokenResponse], error) {
	if s.queryRepo == nil {
		return nil, connect.NewError(connect.CodeUnimplemented,
			errors.New("the configured token store does not support token lookup"))
	}
	token, err := s.queryRepo.GetTokenByID(ctx, req.Msg.GetTokenId())
	if err != nil {
		return nil, connect.NewError(connect.CodeNotFound, errors.New("token not found"))
	}
	if err := s.authorizeTokenAccess(ctx, token); err != nil {
		return nil, err
	}
	var session *domain.Session
	if token.SessionID != "" && s.sessionRepo != nil {
		session, _ = s.sessionRepo.GetSessionByID(ctx, token.SessionID)
	}
	return connect.NewResponse(&ssov1.GetTokenResponse{Token: toUserTokenProto(token, session)}), nil
}

func (s *TokenAdminServer) ListUserDevices(ctx context.Context, req *connect.Request[ssov1.ListUserDevicesRequest]) (*connect.Response[ssov1.ListUserDevicesResponse], error) {
	targetUserID, err := s.resolveTargetUser(ctx, req.Msg.GetUserId(), rbac.PermSessionsListOthers)
	if err != nil {
		return nil, err
	}
	if s.sessionRepo == nil {
		return nil, connect.NewError(connect.CodeUnimplemented, errors.New("session store is not configured"))
	}

	filter := domain.SessionFilter{}
	if !req.Msg.GetIncludeRevoked() {
		revoked := false
		filter.IsRevoked = &revoked
	}
	sessions, err := s.sessionRepo.ListSessionsByUserID(ctx, targetUserID, filter)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to list devices: %w", err))
	}

	now := time.Now().UTC()
	if !req.Msg.GetIncludeExpired() {
		kept := sessions[:0]
		for _, sess := range sessions {
			if sess != nil && now.Before(sess.ExpiresAt) {
				kept = append(kept, sess)
			}
		}
		sessions = kept
	}

	tokensBySession := s.tokensBySession(ctx, targetUserID)
	currentSessionID := ""
	if auth, ok := domain.GetAuthenticatedTokenFromContext(ctx); ok && auth != nil {
		currentSessionID = auth.SessionID
	}

	total := int64(len(sessions))
	limit := int(req.Msg.GetLimit())
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	offset := int(req.Msg.GetOffset())
	if offset < 0 {
		offset = 0
	}
	if offset > len(sessions) {
		offset = len(sessions)
	}
	end := offset + limit
	if end > len(sessions) {
		end = len(sessions)
	}

	out := make([]*ssov1.UserDevice, 0, end-offset)
	for _, sess := range sessions[offset:end] {
		parsed := browserinfo.Parse(sess.UserAgent)
		clients := make([]string, 0)
		if sess.ClientID != "" {
			clients = appendUnique(clients, sess.ClientID)
		}
		active := 0
		for _, t := range tokensBySession[sess.ID] {
			if t.ClientID != "" {
				clients = appendUnique(clients, t.ClientID)
			}
			if tokenStatus(t, now) == ssov1.UserTokenStatus_USER_TOKEN_STATUS_ACTIVE {
				active++
			}
		}
		out = append(out, &ssov1.UserDevice{
			SessionId:        sess.ID,
			UserId:           sess.UserID,
			UserAgent:        sess.UserAgent,
			IpAddress:        sess.IPAddress,
			Browser:          parsed.Browser,
			BrowserVersion:   parsed.Version,
			Os:               parsed.OS,
			DeviceType:       parsed.DeviceType,
			IsRevoked:        sess.IsRevoked,
			IsCurrentSession: currentSessionID != "" && sess.ID == currentSessionID,
			ClientIds:        clients,
			TokenCount:       int32(len(tokensBySession[sess.ID])),
			ActiveTokenCount: int32(active),
		})
		last := out[len(out)-1]
		if !sess.CreatedAt.IsZero() {
			last.CreatedAt = timestamppb.New(sess.CreatedAt)
		}
		if !sess.LastUsedAt.IsZero() {
			last.LastUsedAt = timestamppb.New(sess.LastUsedAt)
		}
		if !sess.ExpiresAt.IsZero() {
			last.ExpiresAt = timestamppb.New(sess.ExpiresAt)
		}
	}
	return connect.NewResponse(&ssov1.ListUserDevicesResponse{
		Devices: out,
		Total:   total,
		Limit:   int32(limit),
		Offset:  int32(offset),
	}), nil
}

func (s *TokenAdminServer) RevokeToken(ctx context.Context, req *connect.Request[ssov1.RevokeTokenRequest]) (*connect.Response[emptypb.Empty], error) {
	if s.queryRepo == nil {
		return nil, connect.NewError(connect.CodeUnimplemented,
			errors.New("the configured token store does not support token lookup"))
	}
	token, err := s.queryRepo.GetTokenByID(ctx, req.Msg.GetTokenId())
	if err != nil {
		return nil, connect.NewError(connect.CodeNotFound, errors.New("token not found"))
	}
	if err := s.authorizeTokenAccess(ctx, token); err != nil {
		return nil, err
	}
	var revokeErr error
	if token.TokenType == domain.TokenTypeRefreshToken {
		if token.Family != "" {
			revokeErr = s.tokenRepo.RevokeTokenFamily(ctx, token.Family)
		} else {
			revokeErr = s.tokenRepo.RevokeRefreshToken(ctx, token.TokenValue)
		}
	} else {
		revokeErr = s.tokenRepo.RevokeToken(ctx, token.TokenValue)
	}
	if revokeErr != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to revoke token: %w", revokeErr))
	}
	info := reqinfo.FromContext(ctx)
	details := "type=" + token.TokenType + " reason=" + strings.TrimSpace(req.Msg.GetReason())
	if d := info.Details(); d != "" {
		details += " " + d
	}
	audit.Log("TokenService", "TokenRevoked", token.UserID, token.ID, details, true, nil)
	return connect.NewResponse(&emptypb.Empty{}), nil
}

func (s *TokenAdminServer) resolveTargetUser(ctx context.Context, requested, otherPermission string) (string, error) {
	auth, ok := domain.GetAuthenticatedTokenFromContext(ctx)
	if !ok || auth == nil {
		return "", connect.NewError(connect.CodeUnauthenticated, errors.New("user not authenticated"))
	}
	target := strings.TrimSpace(requested)
	if target == "" || target == "me" {
		target = auth.UserID
	}
	if target != auth.UserID && !rbac.HasPermission(auth.Roles, otherPermission) {
		return "", connect.NewError(connect.CodePermissionDenied,
			fmt.Errorf("permission denied to inspect tokens for user %s", target))
	}
	return target, nil
}

// authorizeTokenAccess allows a user to inspect/revoke their own tokens and
// requires an admin permission for tokens that have no end user (for example
// client_credentials tokens) or belong to somebody else.
func (s *TokenAdminServer) authorizeTokenAccess(ctx context.Context, token *domain.Token) error {
	auth, ok := domain.GetAuthenticatedTokenFromContext(ctx)
	if !ok || auth == nil {
		return connect.NewError(connect.CodeUnauthenticated, errors.New("user not authenticated"))
	}
	if token.UserID != "" && token.UserID == auth.UserID {
		return nil
	}
	if rbac.HasPermission(auth.Roles, rbac.PermSessionsListOthers) {
		return nil
	}
	return connect.NewError(connect.CodePermissionDenied,
		fmt.Errorf("permission denied to access token %s", token.ID))
}

func (s *TokenAdminServer) sessionCache(ctx context.Context, tokens []*domain.Token) map[string]*domain.Session {
	cache := make(map[string]*domain.Session)
	if s.sessionRepo == nil {
		return cache
	}
	for _, t := range tokens {
		if t == nil || t.SessionID == "" {
			continue
		}
		if _, ok := cache[t.SessionID]; ok {
			continue
		}
		sess, err := s.sessionRepo.GetSessionByID(ctx, t.SessionID)
		if err == nil && sess != nil {
			cache[t.SessionID] = sess
		}
	}
	return cache
}

func (s *TokenAdminServer) tokensBySession(ctx context.Context, userID string) map[string][]*domain.Token {
	out := make(map[string][]*domain.Token)
	if s.queryRepo == nil {
		return out
	}
	// Counts describe the whole device history, so include revoked and expired
	// tokens even when the device list itself hides them.
	tokens, err := s.queryRepo.ListByUserID(ctx, domain.TokenFilter{
		UserID:         userID,
		IncludeRevoked: true,
		IncludeExpired: true,
	}, 1000, 0)
	if err != nil {
		return out
	}
	for _, t := range tokens {
		if t == nil || t.SessionID == "" {
			continue
		}
		out[t.SessionID] = append(out[t.SessionID], t)
	}
	return out
}

func toUserTokenProto(t *domain.Token, sess *domain.Session) *ssov1.UserToken {
	parsed := browserinfo.Parse("")
	if sess != nil {
		parsed = browserinfo.Parse(sess.UserAgent)
	}
	out := &ssov1.UserToken{
		Id:             t.ID,
		TokenType:      t.TokenType,
		ClientId:       t.ClientID,
		UserId:         t.UserID,
		Scope:          t.Scope,
		IsRevoked:      t.IsRevoked,
		SessionId:      t.SessionID,
		Family:         t.Family,
		ParentJti:      t.ParentJTI,
		RotatedTo:      t.RotatedTo,
		Status:         tokenStatus(t, time.Now().UTC()),
		Browser:        parsed.Browser,
		BrowserVersion: parsed.Version,
		Os:             parsed.OS,
		DeviceType:     parsed.DeviceType,
	}
	if sess != nil {
		out.UserAgent = sess.UserAgent
		out.IpAddress = sess.IPAddress
	}
	if !t.CreatedAt.IsZero() {
		out.IssuedAt = timestamppb.New(t.CreatedAt)
	}
	if !t.ExpiresAt.IsZero() {
		out.ExpiresAt = timestamppb.New(t.ExpiresAt)
	}
	if t.UsedAt != nil && !t.UsedAt.IsZero() {
		out.UsedAt = timestamppb.New(*t.UsedAt)
	}
	return out
}

func tokenStatus(t *domain.Token, now time.Time) ssov1.UserTokenStatus {
	switch {
	case t.UsedAt != nil && !t.UsedAt.IsZero():
		// A refresh token that was exchanged is marked used and revoked by the
		// rotation path; "rotated" is the more useful audit state.
		return ssov1.UserTokenStatus_USER_TOKEN_STATUS_ROTATED
	case t.IsRevoked:
		return ssov1.UserTokenStatus_USER_TOKEN_STATUS_REVOKED
	case !t.ExpiresAt.IsZero() && !now.Before(t.ExpiresAt):
		return ssov1.UserTokenStatus_USER_TOKEN_STATUS_EXPIRED
	default:
		return ssov1.UserTokenStatus_USER_TOKEN_STATUS_ACTIVE
	}
}

func appendUnique(list []string, value string) []string {
	for _, v := range list {
		if v == value {
			return list
		}
	}
	list = append(list, value)
	sort.Strings(list)
	return list
}
