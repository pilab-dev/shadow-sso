package graphql

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"time"

	"connectrpc.com/connect"
	"github.com/pilab-dev/shadow-sso/domain"
	"github.com/pilab-dev/shadow-sso/internal/auth/rbac"
)

// Resolver is the root GraphQL resolver. Its dependencies live here (rather
// than in the generated schema.resolvers.go) so gqlgen does not clobber them.
type Resolver struct {
	UserRepo                domain.UserRepository
	UserAttributeRepo       domain.UserAttributeRepository
	UserAttributeMapperRepo domain.UserAttributeMapperRepository
	ClientRepo              domain.ClientRepository
	SessionRepo             domain.SessionRepository
	TokenRepo               domain.TokenRepository
	IdPRepo                 domain.IdPRepository
	GroupRepo               domain.GroupRepository
	RoleRepo                domain.RoleRepository
	ProtocolMapperRepo      domain.ProtocolMapperRepository
	AuthFlowRepo            domain.AuthenticationFlowRepository
	ClientScopeRepo         domain.ClientScopeRepository
	RealmSettingsRepo       domain.RealmSettingsRepository
	RealmKeysRepo           domain.RealmKeysRepository
	EmailService            domain.EmailService
	PasswordHasher          domain.PasswordHasher
	AuditLogRepo            domain.AuditLogRepository
	FederatedIdentityRepo   domain.UserFederatedIdentityRepository
}

func (r *Resolver) resolveRoleNames(ctx context.Context, names []string) []domain.Role {
	roles := make([]domain.Role, 0, len(names))
	for _, name := range names {
		if name == "" {
			continue
		}
		role, err := r.RoleRepo.GetRoleByName(ctx, name)
		if err != nil || role == nil {
			continue
		}
		roles = append(roles, *role)
	}
	return roles
}

func (r *sessionResolver) ClientID(ctx context.Context, obj *domain.Session) (*string, error) {
	// Session doesn't track client ID in domain model
	return nil, nil
}

func requireAdmin(ctx context.Context) error {
	tokenInfo, ok := domain.GetAuthenticatedTokenFromContext(ctx)
	if !ok || tokenInfo == nil {
		return connect.NewError(connect.CodeUnauthenticated, errors.New("authentication required"))
	}
	if !rbac.HasPermission(tokenInfo.Roles, rbac.PermUsersDeleteAll) {
		return connect.NewError(connect.CodePermissionDenied, errors.New("admin role required"))
	}
	return nil
}

func contains(slice []string, val string) bool {
	for _, v := range slice {
		if v == val {
			return true
		}
	}
	return false
}

func generateToken() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func generateRandomSecret() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func ptrInt(i int) *int {
	return &i
}

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

// SessionEvents returns the lifecycle event log for a session.
func (r *queryResolver) SessionEvents(ctx context.Context, sessionID string, first *int) ([]domain.SessionEvent, error) {
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
