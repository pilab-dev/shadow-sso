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
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestAuditServer_ListAuditEvents(t *testing.T) {
	tests := []struct {
		name     string
		reqMsg   *ssov1.ListAuditEventsRequest
		setup    func(t *testing.T, auditRepo *mock_domain.MockAuditLogRepository)
		wantErr  bool
		wantCode connect.Code
	}{
		{
			name:   "lists events with default pagination",
			reqMsg: &ssov1.ListAuditEventsRequest{},
			setup: func(t *testing.T, auditRepo *mock_domain.MockAuditLogRepository) {
				auditRepo.EXPECT().List(gomock.Any(), gomock.Any(), 50, 0).
					Return([]*domain.AuditLog{{ID: "a1", Service: "user", Action: "create", Success: true}}, nil)
				auditRepo.EXPECT().Count(gomock.Any(), gomock.Any()).Return(int64(1), nil)
			},
		},
		{
			name:   "propagates filter and pagination",
			reqMsg: &ssov1.ListAuditEventsRequest{User: "u1", Action: "delete", Limit: 10, Offset: 5},
			setup: func(t *testing.T, auditRepo *mock_domain.MockAuditLogRepository) {
				auditRepo.EXPECT().List(gomock.Any(), gomock.Any(), 10, 5).
					DoAndReturn(func(_ context.Context, f domain.AuditLogFilter, limit, offset int) ([]*domain.AuditLog, error) {
						assert.Equal(t, "u1", f.User)
						assert.Equal(t, "delete", f.Action)
						return nil, nil
					})
				auditRepo.EXPECT().Count(gomock.Any(), gomock.Any()).Return(int64(0), nil)
			},
		},
		{
			name:   "maps time window filter",
			reqMsg: &ssov1.ListAuditEventsRequest{From: timestamppb.New(time.Unix(1000, 0)), To: timestamppb.New(time.Unix(2000, 0))},
			setup: func(t *testing.T, auditRepo *mock_domain.MockAuditLogRepository) {
				auditRepo.EXPECT().List(gomock.Any(), gomock.Any(), 50, 0).
					DoAndReturn(func(_ context.Context, f domain.AuditLogFilter, limit, offset int) ([]*domain.AuditLog, error) {
						require.NotNil(t, f.From)
						require.NotNil(t, f.To)
						assert.Equal(t, int64(1000), f.From.Unix())
						assert.Equal(t, int64(2000), f.To.Unix())
						return nil, nil
					})
				auditRepo.EXPECT().Count(gomock.Any(), gomock.Any()).Return(int64(0), nil)
			},
		},
		{
			name:   "clamps oversize limit and negative offset",
			reqMsg: &ssov1.ListAuditEventsRequest{Limit: 10000, Offset: -1},
			setup: func(t *testing.T, auditRepo *mock_domain.MockAuditLogRepository) {
				auditRepo.EXPECT().List(gomock.Any(), gomock.Any(), 50, 0).
					Return([]*domain.AuditLog{}, nil)
				auditRepo.EXPECT().Count(gomock.Any(), gomock.Any()).Return(int64(0), nil)
			},
		},
		{
			name:   "list error maps to CodeInternal",
			reqMsg: &ssov1.ListAuditEventsRequest{},
			setup: func(t *testing.T, auditRepo *mock_domain.MockAuditLogRepository) {
				auditRepo.EXPECT().List(gomock.Any(), gomock.Any(), 50, 0).Return(nil, errors.New("db down"))
			},
			wantErr:  true,
			wantCode: connect.CodeInternal,
		},
		{
			name:   "count error maps to CodeInternal",
			reqMsg: &ssov1.ListAuditEventsRequest{},
			setup: func(t *testing.T, auditRepo *mock_domain.MockAuditLogRepository) {
				auditRepo.EXPECT().List(gomock.Any(), gomock.Any(), 50, 0).Return(nil, nil)
				auditRepo.EXPECT().Count(gomock.Any(), gomock.Any()).Return(int64(0), errors.New("db down"))
			},
			wantErr:  true,
			wantCode: connect.CodeInternal,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			auditRepo := mock_domain.NewMockAuditLogRepository(ctrl)
			if tt.setup != nil {
				tt.setup(t, auditRepo)
			}

			server := NewAuditServer(auditRepo)
			resp, err := server.ListAuditEvents(context.Background(), connect.NewRequest(tt.reqMsg))
			if tt.wantErr {
				require.Error(t, err)
				assert.Equal(t, tt.wantCode, connect.CodeOf(err))
				return
			}
			require.NoError(t, err)
			require.NotNil(t, resp.Msg)
		})
	}
}

func TestAuditServer_ListAuditEvents_ResponseMapping(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	now := time.Now().UTC()
	auditRepo := mock_domain.NewMockAuditLogRepository(ctrl)
	auditRepo.EXPECT().List(gomock.Any(), gomock.Any(), 50, 0).
		Return([]*domain.AuditLog{{
			ID:        "a1",
			Timestamp: now,
			Service:   "user",
			Action:    "create",
			User:      "u1",
			Target:    "t1",
			Details:   "details",
			Success:   true,
		}}, nil)
	auditRepo.EXPECT().Count(gomock.Any(), gomock.Any()).Return(int64(1), nil)

	server := NewAuditServer(auditRepo)
	resp, err := server.ListAuditEvents(context.Background(), connect.NewRequest(&ssov1.ListAuditEventsRequest{}))
	require.NoError(t, err)

	msg := resp.Msg
	require.Len(t, msg.Events, 1)
	assert.Equal(t, int64(1), msg.Total)
	assert.Equal(t, int32(50), msg.Limit)
	assert.Equal(t, int32(0), msg.Offset)

	ev := msg.Events[0]
	assert.Equal(t, "a1", ev.Id)
	assert.Equal(t, now.Unix(), ev.Timestamp.AsTime().Unix())
	assert.Equal(t, "user", ev.Service)
	assert.Equal(t, "create", ev.Action)
	assert.Equal(t, "u1", ev.User)
	assert.Equal(t, "t1", ev.Target)
	assert.Equal(t, "details", ev.Details)
	assert.True(t, ev.Success)
}
