package client

import (
	"testing"

	"github.com/pilab-dev/shadow-sso/apps/sssoctl/cmd/config"
	"golang.org/x/net/http2"
)

func TestProtocolPrecedence(t *testing.T) {
	old := config.ProtocolOverride
	t.Cleanup(func() { config.ProtocolOverride = old })

	config.ProtocolOverride = ""
	t.Setenv("SSOCTL_PROTOCOL", "")
	if got := protocol(&config.Context{}); got != "connect" {
		t.Fatalf("default protocol = %q, want connect", got)
	}

	if got := protocol(&config.Context{Protocol: "grpc"}); got != "grpc" {
		t.Fatalf("context protocol = %q, want grpc", got)
	}

	t.Setenv("SSOCTL_PROTOCOL", "connect-proto")
	if got := protocol(&config.Context{}); got != "connect-proto" {
		t.Fatalf("env protocol = %q, want connect-proto", got)
	}

	config.ProtocolOverride = "connect"
	if got := protocol(&config.Context{Protocol: "grpc"}); got != "connect" {
		t.Fatalf("flag must win: got %q, want connect", got)
	}
}

func TestNewHTTPClientUsesH2CForPlaintextGRPC(t *testing.T) {
	old := config.ProtocolOverride
	t.Cleanup(func() { config.ProtocolOverride = old })
	config.ProtocolOverride = "grpc"

	c := newHTTPClient(&config.Context{ServerEndpoint: "http://localhost:8080"})
	if _, ok := c.Transport.(*http2.Transport); !ok {
		t.Fatalf("plaintext grpc transport = %T, want *http2.Transport", c.Transport)
	}

	// TLS endpoints use net/http's HTTP/2 support.
	c = newHTTPClient(&config.Context{ServerEndpoint: "https://sso.example"})
	if c.Transport != nil {
		t.Fatalf("tls grpc transport = %T, want nil (default transport)", c.Transport)
	}

	// Connect over plaintext stays on HTTP/1.1.
	config.ProtocolOverride = "connect"
	c = newHTTPClient(&config.Context{ServerEndpoint: "http://localhost:8080"})
	if c.Transport != nil {
		t.Fatalf("connect transport = %T, want nil", c.Transport)
	}
}
