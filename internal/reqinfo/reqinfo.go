// Package reqinfo carries request provenance (user agent, client IP, method and
// path) through the request context. Audit events and session records use it so
// an operator can answer "which device did this come from?" without having to
// correlate access logs by hand.
package reqinfo

import (
	"context"
	"net"
	"net/http"
	"strings"
)

// Info describes where a request came from. It deliberately contains no
// credentials and no token material.
type Info struct {
	UserAgent string
	IP        string
	Method    string
	Path      string
	// Protocol is "connect", "grpc", "grpc-web" or "http".
	Protocol string
	// DPoPProof is the raw DPoP proof JWT from the request, if present.
	DPoPProof string
	// DPoPHTU is the expected htu value for DPoP proof verification.
	DPoPHTU string
}

type contextKey struct{}

// WithContext stores info in ctx.
func WithContext(ctx context.Context, info Info) context.Context {
	return context.WithValue(ctx, contextKey{}, info)
}

// FromContext returns the request info stored in ctx, or the zero value.
func FromContext(ctx context.Context) Info {
	if ctx == nil {
		return Info{}
	}
	if info, ok := ctx.Value(contextKey{}).(Info); ok {
		return info
	}
	return Info{}
}

// FromHeaders builds Info from HTTP headers. It is safe to call with a nil
// header. The transport layer fills IP from the peer when no forwarded header
// is present; see WithPeer.
func FromHeaders(_ context.Context, header http.Header) Info {
	info := Info{Protocol: "connect"}
	if header != nil {
		info.UserAgent = strings.TrimSpace(header.Get("User-Agent"))
		info.IP = clientIPFromHeaders(header)
	}
	return info
}

// WithPeer fills the peer address and protocol when they were not supplied by
// a proxy header.
func WithPeer(info Info, addr, protocol string) Info {
	if info.IP == "" {
		info.IP = hostOnly(addr)
	}
	if protocol != "" {
		info.Protocol = protocol
	}
	return info
}

// FromHTTP builds Info from a net/http request.
func FromHTTP(r *http.Request) Info {
	if r == nil {
		return Info{}
	}
	info := Info{
		Method:    r.Method,
		Path:      r.URL.Path,
		UserAgent: strings.TrimSpace(r.UserAgent()),
		IP:        clientIPFromHeaders(r.Header),
		Protocol:  "http",
	}
	if info.IP == "" {
		info.IP = hostOnly(r.RemoteAddr)
	}
	return info
}

// FromHTTPContext is a convenience for handlers that already copied the
// request context.
func FromHTTPContext(ctx context.Context, r *http.Request) context.Context {
	return WithContext(ctx, FromHTTP(r))
}

// Details renders a compact, human-readable provenance string suitable for an
// audit event's details field.
func (i Info) Details() string {
	parts := make([]string, 0, 4)
	if i.IP != "" {
		parts = append(parts, "ip="+i.IP)
	}
	if i.UserAgent != "" {
		parts = append(parts, "ua="+i.UserAgent)
	}
	if i.Protocol != "" {
		parts = append(parts, "proto="+i.Protocol)
	}
	return strings.Join(parts, " ")
}

func clientIPFromHeaders(h http.Header) string {
	if v := strings.TrimSpace(h.Get("X-Forwarded-For")); v != "" {
		// X-Forwarded-For is a comma-separated chain; the first entry is the
		// original client. Trim quotes and whitespace.
		first := strings.TrimSpace(strings.Split(v, ",")[0])
		return strings.Trim(first, `"`)
	}
	if v := strings.TrimSpace(h.Get("X-Real-IP")); v != "" {
		return strings.Trim(v, `"`)
	}
	if v := strings.TrimSpace(h.Get("Forwarded")); v != "" {
		for _, part := range strings.Split(v, ";") {
			part = strings.TrimSpace(part)
			if strings.HasPrefix(strings.ToLower(part), "for=") {
				return strings.Trim(strings.TrimSpace(part[4:]), `"`)
			}
		}
	}
	return ""
}

func hostOnly(addr string) string {
	if addr == "" {
		return ""
	}
	if host, _, err := net.SplitHostPort(addr); err == nil {
		return host
	}
	return addr
}
