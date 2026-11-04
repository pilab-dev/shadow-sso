package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/pilab-dev/shadow-sso/domain"
	mock_domain "github.com/pilab-dev/shadow-sso/domain/mocks"
	ssov1 "github.com/pilab-dev/shadow-sso/gen/proto/sso/v1"
	"github.com/pilab-dev/shadow-sso/gen/proto/sso/v1/ssov1connect"
	"github.com/pilab-dev/shadow-sso/services"
	mock_services "github.com/pilab-dev/shadow-sso/services/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestStreamingInterceptors_EnforceAuthAndRBAC(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	tokenService := mock_services.NewMockTokenService(ctrl)
	tokenService.EXPECT().ValidateAccessToken(gomock.Any(), "user-token").Return(&domain.Token{
		ID:        "jti",
		UserID:    "u1",
		ExpiresAt: time.Now().Add(time.Hour),
		Roles:     []string{"ROLE_USER"},
	}, nil).AnyTimes()
	tokenService.EXPECT().ValidateAccessToken(gomock.Any(), "admin-token").Return(&domain.Token{
		ID:        "jti",
		UserID:    "admin",
		ExpiresAt: time.Now().Add(time.Hour),
		Roles:     []string{"ROLE_ADMIN"},
	}, nil).AnyTimes()

	auditRepo := mock_domain.NewMockAuditLogRepository(ctrl)
	auditRepo.EXPECT().ListAfter(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
		Return([]*domain.AuditLog{{
			ID: "a1", Timestamp: time.Now().UTC(), Service: "S", Action: "A", Success: true,
		}}, nil).AnyTimes()

	server := services.NewAuditServer(auditRepo)
	path, handler := ssov1connect.NewAuditServiceHandler(server, connect.WithInterceptors(
		NewAuthInterceptor(tokenService),
		NewAuthorizationInterceptor(),
	))
	mux := http.NewServeMux()
	mux.Handle(path, handler)
	ts := httptest.NewServer(mux)
	defer ts.Close()

	req := &ssov1.FollowAuditEventsRequest{
		From:            timestamppb.New(time.Now().Add(-time.Minute)),
		IncludeExisting: true,
		PollIntervalMs:  250,
		BatchSize:       10,
	}

	t.Run("missing token is unauthenticated", func(t *testing.T) {
		client := ssov1connect.NewAuditServiceClient(ts.Client(), ts.URL)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		stream, err := client.FollowAuditEvents(ctx, connect.NewRequest(req))
		require.NoError(t, err)
		for stream.Receive() {
		}
		require.Error(t, stream.Err())
		assert.Equal(t, connect.CodeUnauthenticated, connect.CodeOf(stream.Err()))
	})

	t.Run("non-admin is permission denied", func(t *testing.T) {
		client := ssov1connect.NewAuditServiceClient(ts.Client(), ts.URL,
			connect.WithInterceptors(bearerInterceptor("user-token")))
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		stream, err := client.FollowAuditEvents(ctx, connect.NewRequest(req))
		require.NoError(t, err)
		for stream.Receive() {
		}
		require.Error(t, stream.Err())
		assert.Equal(t, connect.CodePermissionDenied, connect.CodeOf(stream.Err()))
	})

	t.Run("admin can follow", func(t *testing.T) {
		client := ssov1connect.NewAuditServiceClient(ts.Client(), ts.URL,
			connect.WithInterceptors(bearerInterceptor("admin-token")))
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		stream, err := client.FollowAuditEvents(ctx, connect.NewRequest(req))
		require.NoError(t, err)
		require.True(t, stream.Receive())
		assert.Equal(t, "a1", stream.Msg().GetId())
		stream.Close()
	})
}

type bearerInterceptor string

func (b bearerInterceptor) WrapUnary(next connect.UnaryFunc) connect.UnaryFunc {
	return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
		req.Header().Set("Authorization", "Bearer "+string(b))
		return next(ctx, req)
	}
}
func (b bearerInterceptor) WrapStreamingClient(next connect.StreamingClientFunc) connect.StreamingClientFunc {
	return func(ctx context.Context, spec connect.Spec) connect.StreamingClientConn {
		conn := next(ctx, spec)
		conn.RequestHeader().Set("Authorization", "Bearer "+string(b))
		return conn
	}
}
func (b bearerInterceptor) WrapStreamingHandler(next connect.StreamingHandlerFunc) connect.StreamingHandlerFunc {
	return next
}
