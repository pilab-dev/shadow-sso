package graphql

import (
	"context"
	"errors"
	"time"

	"connectrpc.com/connect"
	"github.com/pilab-dev/shadow-sso/domain"
	"github.com/pilab-dev/shadow-sso/internal/auth/rbac"
)

// Current reports whether obj is the caller's current session.
func (r *sessionResolver) Current(ctx context.Context, obj *domain.Session) (*bool, error) {
	info, ok := domain.GetAuthenticatedTokenFromContext(ctx)
	if !ok || info == nil || obj == nil {
		v := false
		return &v, nil
	}
	v := info.SessionID == obj.ID || (info.ID != "" && info.ID == obj.TokenID)
	return &v, nil
}

// RevokeOtherSessions revokes every session for a user except the caller's (or
// the explicitly provided) session.
func (r *mutationResolver) RevokeOtherSessions(ctx context.Context, userID string, exceptSessionID *string) (int, error) {
	if err := requireAdmin(ctx); err != nil {
		return 0, err
	}
	keep := ""
	if exceptSessionID != nil {
		keep = *exceptSessionID
	} else if info, ok := domain.GetAuthenticatedTokenFromContext(ctx); ok && info != nil {
		keep = info.SessionID
	}
	sessions, err := r.SessionRepo.ListSessionsByUserID(ctx, userID, domain.SessionFilter{})
	if err != nil {
		return 0, err
	}
	now := time.Now().UTC()
	revoked := 0
	for _, s := range sessions {
		if s.ID == keep {
			continue
		}
		s.IsRevoked = true
		s.RevokedAt = &now
		s.RevokedBy = "user"
		s.RevokeReason = "revokeOtherSessions"
		if err := r.SessionRepo.UpdateSession(ctx, s); err != nil {
			return revoked, err
		}
		if r.TokenRepo != nil {
			if err := r.TokenRepo.RevokeTokensBySessionID(ctx, s.ID); err != nil {
				return revoked, err
			}
		}
		_ = r.SessionRepo.StoreSessionEvent(ctx, &domain.SessionEvent{
			SessionID: s.ID,
			UserID:    s.UserID,
			ClientID:  s.ClientID,
			Type:      "revoked",
			At:        now,
			Actor:     "user",
			Reason:    "revokeOtherSessions",
		})
		revoked++
	}
	return revoked, nil
}

// SessionEvents returns the lifecycle event log for a session. Admins may read
// any session; other callers may only read their own.
func (r *queryResolver) SessionEvents(ctx context.Context, sessionID string, first *int) ([]domain.SessionEvent, error) {
	info, ok := domain.GetAuthenticatedTokenFromContext(ctx)
	if !ok || info == nil {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("authentication required"))
	}
	session, err := r.SessionRepo.GetSessionByID(ctx, sessionID)
	if err != nil {
		return nil, err
	}
	if session.UserID != info.UserID && !rbac.HasPermission(info.Roles, rbac.PermUsersDeleteAll) {
		return nil, connect.NewError(connect.CodePermissionDenied, errors.New("admin role required"))
	}
	limit := 50
	if first != nil && *first > 0 {
		limit = *first
	}
	events, err := r.SessionRepo.ListSessionEvents(ctx, sessionID, limit)
	if err != nil {
		return nil, err
	}
	out := make([]domain.SessionEvent, len(events))
	for i, e := range events {
		out[i] = *e
	}
	return out, nil
}
