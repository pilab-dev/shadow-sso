package middleware

import (
	"context"

	"connectrpc.com/connect"
	"github.com/pilab-dev/shadow-sso/internal/reqinfo"
)

// RequestInfoInterceptor stores request provenance (user agent, peer IP and
// protocol) in the context so services can attach it to audit events and
// session records without reaching into transport-specific types.
func RequestInfoInterceptor() connect.Interceptor {
	return requestInfoInterceptor{}
}

type requestInfoInterceptor struct{}

func (requestInfoInterceptor) WrapUnary(next connect.UnaryFunc) connect.UnaryFunc {
	return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
		peer := req.Peer()
		info := reqinfo.WithPeer(reqinfo.FromHeaders(ctx, req.Header()), peer.Addr, peer.Protocol)
		return next(reqinfo.WithContext(ctx, info), req)
	}
}

func (requestInfoInterceptor) WrapStreamingClient(next connect.StreamingClientFunc) connect.StreamingClientFunc {
	return next
}

func (requestInfoInterceptor) WrapStreamingHandler(next connect.StreamingHandlerFunc) connect.StreamingHandlerFunc {
	return func(ctx context.Context, conn connect.StreamingHandlerConn) error {
		peer := conn.Peer()
		info := reqinfo.WithPeer(reqinfo.FromHeaders(ctx, conn.RequestHeader()), peer.Addr, peer.Protocol)
		return next(reqinfo.WithContext(ctx, info), conn)
	}
}
