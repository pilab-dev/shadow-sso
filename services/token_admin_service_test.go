package services

import (
	"context"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/pilab-dev/shadow-sso/domain"
	mock_domain "github.com/pilab-dev/shadow-sso/domain/mocks"
	ssov1 "github.com/pilab-dev/shadow-sso/gen/proto/sso/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

type fakeTokenRepo struct {
	domain.TokenRepository
	tokens   []*domain.Token
	revoked  []string
	queryErr error
}

func (f *fakeTokenRepo) ListByUserID(_ context.Context, filter domain.TokenFilter, limit, offset int) ([]*domain.Token, error) {
	if f.queryErr != nil {
		return nil, f.queryErr
	}
	out := make([]*domain.Token, 0, len(f.tokens))
	for _, t := range f.tokens {
		if filter.UserID != "" && t.UserID != filter.UserID {
			continue
		}
		if filter.SessionID != "" && t.SessionID != filter.SessionID {
			continue
		}
		if filter.TokenType != "" && t.TokenType != filter.TokenType {
			continue
		}
		if !filter.IncludeRevoked && t.IsRevoked {
			continue
		}
		out = append(out, t)
	}
	return out, nil
}

func (f *fakeTokenRepo) CountByUserID(ctx context.Context, filter domain.TokenFilter) (int64, error) {
	tokens, err := f.ListByUserID(ctx, filter, 1000, 0)
	return int64(len(tokens)), err
}

func (f *fakeTokenRepo) GetTokenByID(_ context.Context, id string) (*domain.Token, error) {
	for _, t := range f.tokens {
		if t.ID == id {
			return t, nil
		}
	}
	return nil, context.Canceled
}

func (f *fakeTokenRepo) RevokeToken(_ context.Context, tokenValue string) error {
	f.revoked = append(f.revoked, tokenValue)
	return nil
}

func (f *fakeTokenRepo) ListUnauditedExpired(_ context.Context, _ time.Time, _ int) ([]*domain.Token, error) {
	return nil, nil
}

func (f *fakeTokenRepo) MarkExpiryAudited(_ context.Context, _ []string) error { return nil }

func authContext(userID, sessionID, role string) context.Context {
	return context.WithValue(context.Background(), domain.TokenContextKey, &domain.TokenInfo{
		ID:        "caller-jti",
		UserID:    userID,
		SessionID: sessionID,
		Roles:     []string{role},
	})
}

func TestTokenAdminServer_ListUserTokens_Self(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	now := time.Now().UTC()
	repo := &fakeTokenRepo{tokens: []*domain.Token{
		{
			ID:         "jti-1",
			TokenType:  "access_token",
			ClientID:   "app",
			UserID:     "u1",
			Scope:      "openid",
			CreatedAt:  now.Add(-time.Minute),
			ExpiresAt:  now.Add(time.Hour),
			SessionID:  "s1",
			TokenValue: "secret-value-must-not-leak",
		},
		{
			ID:        "jti-2",
			TokenType: "refresh_token",
			UserID:    "u1",
			CreatedAt: now.Add(-2 * time.Minute),
			ExpiresAt: now.Add(-time.Minute),
			SessionID: "s1",
		},
	}}
	sessions := mock_domain.NewMockSessionRepository(ctrl)
	sessions.EXPECT().GetSessionByID(gomock.Any(), "s1").
		Return(&domain.Session{ID: "s1", UserID: "u1", UserAgent: "Mozilla/5.0 (Windows NT 10.0) Chrome/126.0.0.0 Safari/537.36", IPAddress: "10.0.0.1"}, nil).
		AnyTimes()

	server := NewTokenAdminServer(repo, sessions)
	resp, err := server.ListUserTokens(authContext("u1", "s1", "ROLE_USER"),
		connect.NewRequest(&ssov1.ListUserTokensRequest{UserId: "me", IncludeExpired: true}))
	require.NoError(t, err)
	require.Len(t, resp.Msg.GetTokens(), 2)

	first := resp.Msg.GetTokens()[0]
	assert.Equal(t, "jti-1", first.GetId())
	assert.Equal(t, ssov1.UserTokenStatus_USER_TOKEN_STATUS_ACTIVE, first.GetStatus())
	assert.Equal(t, "chrome", first.GetBrowser())
	assert.Equal(t, "s1", first.GetSessionId())
	assert.NotContains(t, first.String(), "secret-value")
	assert.Equal(t, ssov1.UserTokenStatus_USER_TOKEN_STATUS_EXPIRED, resp.Msg.GetTokens()[1].GetStatus())
}

func TestTokenAdminServer_ListUserTokens_OtherUserRequiresPermission(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	server := NewTokenAdminServer(&fakeTokenRepo{}, mock_domain.NewMockSessionRepository(ctrl))
	_, err := server.ListUserTokens(authContext("u1", "s1", "ROLE_USER"),
		connect.NewRequest(&ssov1.ListUserTokensRequest{UserId: "u2"}))
	require.Error(t, err)
	assert.Equal(t, connect.CodePermissionDenied, connect.CodeOf(err))
}

func TestTokenAdminServer_ListUserDevices(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	now := time.Now().UTC()
	repo := &fakeTokenRepo{tokens: []*domain.Token{
		{ID: "jti-1", UserID: "u1", SessionID: "s1", TokenType: "access_token", ExpiresAt: now.Add(time.Hour), ClientID: "app"},
		{ID: "jti-2", UserID: "u1", SessionID: "s1", TokenType: "refresh_token", ExpiresAt: now.Add(time.Hour), IsRevoked: true, ClientID: "app"},
	}}
	sessions := mock_domain.NewMockSessionRepository(ctrl)
	sessions.EXPECT().ListSessionsByUserID(gomock.Any(), "u1", gomock.Any()).Return([]*domain.Session{
		{ID: "s1", UserID: "u1", UserAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Version/17.5 Safari/605.1.15", ExpiresAt: now.Add(time.Hour), LastUsedAt: now},
		{ID: "s2", UserID: "u1", UserAgent: "ssoctl/1.1.0", ExpiresAt: now.Add(time.Hour)},
	}, nil)

	server := NewTokenAdminServer(repo, sessions)
	resp, err := server.ListUserDevices(authContext("u1", "s1", "ROLE_USER"),
		connect.NewRequest(&ssov1.ListUserDevicesRequest{UserId: "me"}))
	require.NoError(t, err)
	require.Len(t, resp.Msg.GetDevices(), 2)

	assert.Equal(t, int32(2), resp.Msg.GetDevices()[0].GetTokenCount())
	assert.Equal(t, int32(1), resp.Msg.GetDevices()[0].GetActiveTokenCount())
	assert.True(t, resp.Msg.GetDevices()[0].GetIsCurrentSession())
	assert.Equal(t, "safari", resp.Msg.GetDevices()[0].GetBrowser())
	assert.Equal(t, "ssoctl", resp.Msg.GetDevices()[1].GetBrowser())
}

func TestTokenAdminServer_RevokeToken(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	repo := &fakeTokenRepo{tokens: []*domain.Token{{
		ID: "jti-1", UserID: "u1", TokenValue: "raw-token", TokenType: "access_token",
		ExpiresAt: time.Now().Add(time.Hour),
	}}}
	server := NewTokenAdminServer(repo, mock_domain.NewMockSessionRepository(ctrl))
	_, err := server.RevokeToken(authContext("u1", "s1", "ROLE_USER"),
		connect.NewRequest(&ssov1.RevokeTokenRequest{TokenId: "jti-1", Reason: "lost laptop"}))
	require.NoError(t, err)
	assert.Equal(t, []string{"raw-token"}, repo.revoked)
}
