package services

import (
	"context"
	"errors"
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

func TestSessionAdmin_ListClientUserSessionsFilters(t *testing.T) {
	ctrl := gomock.NewController(t)
	sessRepo := mock_domain.NewMockSessionRepository(ctrl)
	sessRepo.EXPECT().ListSessionsByUserID(gomock.Any(), "u1", gomock.Any()).Return([]*domain.Session{
		{ID: "s1", UserID: "u1", ClientID: "c1"},
		{ID: "s2", UserID: "u1", ClientID: "c2", IsRevoked: true},
	}, nil)
	server := NewSessionAdminServer(sessRepo, nil)

	resp, err := server.ListClientUserSessions(context.Background(), connect.NewRequest(&ssov1.ListClientUserSessionsRequest{UserId: "u1", ClientId: "c1"}))
	require.NoError(t, err)
	require.Len(t, resp.Msg.Sessions, 1)
	assert.Equal(t, "s1", resp.Msg.Sessions[0].Id)
	assert.Equal(t, "active", resp.Msg.Sessions[0].State)
}

func TestSessionAdmin_RevokeSession(t *testing.T) {
	ctrl := gomock.NewController(t)
	sessRepo := mock_domain.NewMockSessionRepository(ctrl)
	tokenRepo := mock_domain.NewMockTokenRepository(ctrl)
	sessRepo.EXPECT().GetSessionByID(gomock.Any(), "s1").Return(&domain.Session{ID: "s1", UserID: "u1"}, nil)
	sessRepo.EXPECT().UpdateSession(gomock.Any(), gomock.Any()).DoAndReturn(func(_ context.Context, s *domain.Session) error {
		assert.True(t, s.IsRevoked)
		assert.NotNil(t, s.RevokedAt)
		return nil
	})
	tokenRepo.EXPECT().RevokeTokensBySessionID(gomock.Any(), "s1").Return(nil)
	sessRepo.EXPECT().StoreSessionEvent(gomock.Any(), gomock.Any()).Return(nil)
	server := NewSessionAdminServer(sessRepo, tokenRepo)

	resp, err := server.RevokeSession(context.Background(), connect.NewRequest(&ssov1.RevokeSessionRequest{SessionId: "s1"}))
	require.NoError(t, err)
	assert.True(t, resp.Msg.Success)
}

func TestSessionAdmin_RevokeSessionNotFound(t *testing.T) {
	ctrl := gomock.NewController(t)
	sessRepo := mock_domain.NewMockSessionRepository(ctrl)
	sessRepo.EXPECT().GetSessionByID(gomock.Any(), "nope").Return(nil, domain.ErrSessionNotFound)
	server := NewSessionAdminServer(sessRepo, nil)

	_, err := server.RevokeSession(context.Background(), connect.NewRequest(&ssov1.RevokeSessionRequest{SessionId: "nope"}))
	require.Error(t, err)
	assert.Equal(t, connect.CodeNotFound, connect.CodeOf(err))
}

func TestSessionAdmin_RevokeOtherSessionsKeepsExcepted(t *testing.T) {
	ctrl := gomock.NewController(t)
	sessRepo := mock_domain.NewMockSessionRepository(ctrl)
	sessRepo.EXPECT().ListSessionsByUserID(gomock.Any(), "u1", gomock.Any()).Return([]*domain.Session{
		{ID: "keep", UserID: "u1"}, {ID: "drop", UserID: "u1"},
	}, nil)
	sessRepo.EXPECT().UpdateSession(gomock.Any(), gomock.Any()).DoAndReturn(func(_ context.Context, s *domain.Session) error {
		assert.Equal(t, "drop", s.ID)
		return nil
	})
	sessRepo.EXPECT().StoreSessionEvent(gomock.Any(), gomock.Any()).Return(nil)
	server := NewSessionAdminServer(sessRepo, nil)

	keep := "keep"
	resp, err := server.RevokeOtherSessions(context.Background(), connect.NewRequest(&ssov1.RevokeOtherSessionsRequest{UserId: "u1", ExceptSessionId: &keep}))
	require.NoError(t, err)
	assert.Equal(t, int32(1), resp.Msg.RevokedCount)
}

func TestSessionAdmin_LogoutUserDeletesAndRevokesTokens(t *testing.T) {
	ctrl := gomock.NewController(t)
	sessRepo := mock_domain.NewMockSessionRepository(ctrl)
	tokenRepo := mock_domain.NewMockTokenRepository(ctrl)
	sessRepo.EXPECT().ListSessionsByUserID(gomock.Any(), "u1", gomock.Any()).Return([]*domain.Session{{ID: "s1"}}, nil)
	sessRepo.EXPECT().DeleteSessionsByUserID(gomock.Any(), "u1").Return(int64(1), nil)
	tokenRepo.EXPECT().RevokeTokensBySessionID(gomock.Any(), "s1").Return(nil)
	server := NewSessionAdminServer(sessRepo, tokenRepo)

	resp, err := server.LogoutUser(context.Background(), connect.NewRequest(&ssov1.LogoutUserRequest{UserId: "u1"}))
	require.NoError(t, err)
	assert.True(t, resp.Msg.Success)
}

func TestSessionAdmin_ListSessionEvents(t *testing.T) {
	ctrl := gomock.NewController(t)
	sessRepo := mock_domain.NewMockSessionRepository(ctrl)
	sessRepo.EXPECT().GetSessionByID(gomock.Any(), "s1").Return(&domain.Session{ID: "s1"}, nil)
	sessRepo.EXPECT().ListSessionEvents(gomock.Any(), "s1", 50).Return([]*domain.SessionEvent{
		{ID: "e1", SessionID: "s1", Type: "created", At: time.Now()},
	}, nil)
	server := NewSessionAdminServer(sessRepo, nil)

	resp, err := server.ListSessionEvents(context.Background(), connect.NewRequest(&ssov1.ListSessionEventsRequest{SessionId: "s1"}))
	require.NoError(t, err)
	require.Len(t, resp.Msg.Events, 1)
	assert.Equal(t, "created", resp.Msg.Events[0].Type)

	sessRepo.EXPECT().GetSessionByID(gomock.Any(), "x").Return(nil, errors.New("session not found"))
	_, err = server.ListSessionEvents(context.Background(), connect.NewRequest(&ssov1.ListSessionEventsRequest{SessionId: "x"}))
	assert.Equal(t, connect.CodeNotFound, connect.CodeOf(err))
}
