package server

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"testing"
	"time"

	"connectrpc.com/connect"
	ssov1 "github.com/pilab-dev/shadow-sso/gen/proto/sso/v1"
	"github.com/pilab-dev/shadow-sso/gen/proto/sso/v1/ssov1connect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/http2"
)

// stubAuthService implements just enough of AuthService to prove the transport
// works; no database or business logic involved.
type stubAuthService struct {
	ssov1connect.UnimplementedAuthServiceHandler
}

func (stubAuthService) ListUserSessions(_ context.Context, req *connect.Request[ssov1.ListUserSessionsRequest]) (*connect.Response[ssov1.ListUserSessionsResponse], error) {
	return connect.NewResponse(&ssov1.ListUserSessionsResponse{
		Sessions: []*ssov1.SessionInfo{{Id: "session-1", UserId: req.Msg.GetUserId()}},
	}), nil
}

// TestH2CHandlerServesConnectAndGRPC verifies that the exact wrapper used by the
// production server accepts both a Connect+JSON client and a native gRPC client
// on the same plaintext port.
func TestH2CHandlerServesConnectAndGRPC(t *testing.T) {
	mux := http.NewServeMux()
	path, handler := ssov1connect.NewAuthServiceHandler(stubAuthService{})
	mux.Handle(path, handler)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	srv := &http.Server{Handler: newH2CHandler(mux)}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})

	baseURL := "http://" + ln.Addr().String()
	req := &ssov1.ListUserSessionsRequest{UserId: "user-1"}

	t.Run("connect json", func(t *testing.T) {
		client := ssov1connect.NewAuthServiceClient(&http.Client{}, baseURL, connect.WithProtoJSON())
		resp, err := client.ListUserSessions(context.Background(), connect.NewRequest(req))
		require.NoError(t, err)
		require.Len(t, resp.Msg.GetSessions(), 1)
		assert.Equal(t, "user-1", resp.Msg.GetSessions()[0].GetUserId())
	})

	t.Run("native grpc over h2c", func(t *testing.T) {
		client := ssov1connect.NewAuthServiceClient(h2cClient(), baseURL, connect.WithGRPC())
		resp, err := client.ListUserSessions(context.Background(), connect.NewRequest(req))
		require.NoError(t, err)
		require.Len(t, resp.Msg.GetSessions(), 1)
		assert.Equal(t, "user-1", resp.Msg.GetSessions()[0].GetUserId())
	})
}

func h2cClient() *http.Client {
	return &http.Client{Transport: &http2.Transport{
		AllowHTTP: true,
		DialTLSContext: func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, addr)
		},
	}}
}
