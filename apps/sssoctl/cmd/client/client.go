package client

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"

	"connectrpc.com/connect"
	"github.com/pilab-dev/shadow-sso/apps/sssoctl/cmd/config"
	"github.com/pilab-dev/shadow-sso/gen/proto/sso/v1/ssov1connect"
	"golang.org/x/net/http2"
)

// protocol resolves the wire protocol for proto-based RPCs. Precedence:
// --protocol flag, context setting, SSOCTL_PROTOCOL, then Connect+JSON.
func protocol(cfg *config.Context) string {
	p := strings.ToLower(strings.TrimSpace(config.ProtocolOverride))
	if p == "" && cfg != nil {
		p = strings.ToLower(strings.TrimSpace(cfg.Protocol))
	}
	if p == "" {
		p = strings.ToLower(strings.TrimSpace(os.Getenv("SSOCTL_PROTOCOL")))
	}
	switch p {
	case "grpc":
		return "grpc"
	case "connect-proto", "connect-binary", "binary":
		return "connect-proto"
	default:
		return "connect"
	}
}

// clientOptions returns the codec/protocol options for the selected protocol.
func clientOptions(cfg *config.Context) []connect.ClientOption {
	switch protocol(cfg) {
	case "grpc":
		return []connect.ClientOption{connect.WithGRPC()}
	case "connect-proto":
		// Connect's default codec is protobuf binary.
		return nil
	default:
		return []connect.ClientOption{connect.WithProtoJSON()}
	}
}

// options adds the bearer-token interceptor when a token is available.
func options(cfg *config.Context) []connect.ClientOption {
	opts := clientOptions(cfg)
	if cfg != nil && cfg.UserAuthToken != "" {
		opts = append(opts, connect.WithInterceptors(&authInterceptor{token: cfg.UserAuthToken}))
	}
	return opts
}

// newHTTPClient returns a client capable of the selected protocol. gRPC over a
// plaintext endpoint needs HTTP/2 with prior knowledge (h2c), which net/http
// does not enable by itself.
func newHTTPClient(cfg *config.Context) *http.Client {
	if protocol(cfg) == "grpc" && cfg != nil && strings.HasPrefix(strings.ToLower(cfg.ServerEndpoint), "http://") {
		return &http.Client{Transport: &http2.Transport{
			AllowHTTP: true,
			DialTLSContext: func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, network, addr)
			},
		}}
	}
	return &http.Client{}
}

// AuthServiceClient returns a new AuthService client.
func AuthServiceClient(cfg *config.Context) (ssov1connect.AuthServiceClient, error) {
	if cfg == nil || cfg.ServerEndpoint == "" {
		return nil, fmt.Errorf("invalid context or server endpoint for AuthService client")
	}
	httpClient := newHTTPClient(cfg)
	opts := options(cfg)

	return ssov1connect.NewAuthServiceClient(httpClient, cfg.ServerEndpoint, opts...), nil
}

// UserServiceClient returns a new UserService client.
func UserServiceClient(cfg *config.Context) (ssov1connect.UserServiceClient, error) {
	if cfg == nil || cfg.ServerEndpoint == "" {
		return nil, fmt.Errorf("invalid context or server endpoint for UserService client")
	}
	if cfg.UserAuthToken == "" { // Most user commands will require auth
		return nil, fmt.Errorf("user authentication token not found in current context. Please login using 'ssoctl auth login'")
	}
	httpClient := newHTTPClient(cfg)
	opts := options(cfg)
	return ssov1connect.NewUserServiceClient(httpClient, cfg.ServerEndpoint, opts...), nil
}

// ServiceAccountServiceClient returns a new ServiceAccountService client.
func ServiceAccountServiceClient(cfg *config.Context) (ssov1connect.ServiceAccountServiceClient, error) {
	if cfg == nil || cfg.ServerEndpoint == "" {
		return nil, fmt.Errorf("invalid context or server endpoint for ServiceAccountService client")
	}
	if cfg.UserAuthToken == "" { // Service account management requires auth
		return nil, fmt.Errorf("user authentication token not found in current context. Please login using 'ssoctl auth login'")
	}
	httpClient := newHTTPClient(cfg)
	opts := options(cfg)
	return ssov1connect.NewServiceAccountServiceClient(httpClient, cfg.ServerEndpoint, opts...), nil
}

// ClientManagementServiceClient returns a new ClientManagementService client.
func ClientManagementServiceClient(cfg *config.Context) (ssov1connect.ClientManagementServiceClient, error) {
	if cfg == nil || cfg.ServerEndpoint == "" {
		return nil, fmt.Errorf("invalid context or server endpoint for ClientManagementService client")
	}
	if cfg.UserAuthToken == "" { // Client management requires auth (admin)
		return nil, fmt.Errorf("user authentication token not found in current context. Please login using 'ssoctl auth login'")
	}
	httpClient := newHTTPClient(cfg)
	opts := options(cfg)
	return ssov1connect.NewClientManagementServiceClient(httpClient, cfg.ServerEndpoint, opts...), nil
}

// IdPManagementServiceClient returns a new IdPManagementService client.
func IdPManagementServiceClient(cfg *config.Context) (ssov1connect.IdPManagementServiceClient, error) {
	if cfg == nil || cfg.ServerEndpoint == "" {
		return nil, fmt.Errorf("invalid context or server endpoint for IdPManagementService client")
	}
	if cfg.UserAuthToken == "" { // IdP management requires auth (admin)
		return nil, fmt.Errorf("user authentication token not found in current context. Please login using 'ssoctl auth login'")
	}
	httpClient := newHTTPClient(cfg)
	opts := options(cfg)
	return ssov1connect.NewIdPManagementServiceClient(httpClient, cfg.ServerEndpoint, opts...), nil
}

// TwoFactorServiceClient returns a new TwoFactorService client.
func TwoFactorServiceClient(cfg *config.Context) (ssov1connect.TwoFactorServiceClient, error) {
	if cfg == nil || cfg.ServerEndpoint == "" {
		return nil, fmt.Errorf("invalid context or server endpoint for TwoFactorService client")
	}
	if cfg.UserAuthToken == "" { // 2FA self-management requires auth
		return nil, fmt.Errorf("user authentication token not found in current context. Please login using 'ssoctl auth login'")
	}
	httpClient := newHTTPClient(cfg)
	opts := options(cfg)
	return ssov1connect.NewTwoFactorServiceClient(httpClient, cfg.ServerEndpoint, opts...), nil
}

// FederationServiceClient returns a new FederationService client.
func FederationServiceClient(cfg *config.Context) (ssov1connect.FederationServiceClient, error) {
	if cfg == nil || cfg.ServerEndpoint == "" {
		return nil, fmt.Errorf("invalid context or server endpoint for FederationService client")
	}
	if cfg.UserAuthToken == "" { // Federated identity self-management requires auth
		return nil, fmt.Errorf("user authentication token not found in current context. Please login using 'ssoctl auth login'")
	}
	httpClient := newHTTPClient(cfg)
	opts := options(cfg)
	return ssov1connect.NewFederationServiceClient(httpClient, cfg.ServerEndpoint, opts...), nil
}

// AuditServiceClient returns a new AuditService client.
func AuditServiceClient(cfg *config.Context) (ssov1connect.AuditServiceClient, error) {
	if cfg == nil || cfg.ServerEndpoint == "" {
		return nil, fmt.Errorf("invalid context or server endpoint for AuditService client")
	}
	if cfg.UserAuthToken == "" {
		return nil, fmt.Errorf("user authentication token not found in current context. Please login using 'ssoctl auth login'")
	}
	httpClient := newHTTPClient(cfg)
	opts := options(cfg)
	return ssov1connect.NewAuditServiceClient(httpClient, cfg.ServerEndpoint, opts...), nil
}

// TokenServiceClient returns a traceability client for token/device listings.
func TokenServiceClient(cfg *config.Context) (ssov1connect.TokenServiceClient, error) {
	if cfg == nil || cfg.ServerEndpoint == "" {
		return nil, fmt.Errorf("invalid context or server endpoint for TokenService client")
	}
	if cfg.UserAuthToken == "" {
		return nil, fmt.Errorf("user authentication token not found in current context. Please login using 'ssoctl auth login'")
	}
	httpClient := newHTTPClient(cfg)
	opts := options(cfg)
	return ssov1connect.NewTokenServiceClient(httpClient, cfg.ServerEndpoint, opts...), nil
}

// BrowserPolicyServiceClient returns the enterprise browser-baseline client.
func BrowserPolicyServiceClient(cfg *config.Context) (ssov1connect.BrowserPolicyServiceClient, error) {
	if cfg == nil || cfg.ServerEndpoint == "" {
		return nil, fmt.Errorf("invalid context or server endpoint for BrowserPolicyService client")
	}
	if cfg.UserAuthToken == "" {
		return nil, fmt.Errorf("user authentication token not found in current context. Please login using 'ssoctl auth login'")
	}
	httpClient := newHTTPClient(cfg)
	opts := options(cfg)
	return ssov1connect.NewBrowserPolicyServiceClient(httpClient, cfg.ServerEndpoint, opts...), nil
}

// UserAttributeServiceClient returns a new UserAttributeService client.
func UserAttributeServiceClient(cfg *config.Context) (ssov1connect.UserAttributeServiceClient, error) {
	if cfg == nil || cfg.ServerEndpoint == "" {
		return nil, fmt.Errorf("invalid context or server endpoint for UserAttributeService client")
	}
	if cfg.UserAuthToken == "" { // User attribute management requires auth (admin)
		return nil, fmt.Errorf("user authentication token not found in current context. Please login using 'ssoctl auth login'")
	}
	httpClient := newHTTPClient(cfg)
	opts := options(cfg)
	return ssov1connect.NewUserAttributeServiceClient(httpClient, cfg.ServerEndpoint, opts...), nil
}

// UserAttributeMapperServiceClient returns a new UserAttributeMapperService client.
func UserAttributeMapperServiceClient(cfg *config.Context) (ssov1connect.UserAttributeMapperServiceClient, error) {
	if cfg == nil || cfg.ServerEndpoint == "" {
		return nil, fmt.Errorf("invalid context or server endpoint for UserAttributeMapperService client")
	}
	if cfg.UserAuthToken == "" { // Token mapper management requires auth (admin)
		return nil, fmt.Errorf("user authentication token not found in current context. Please login using 'ssoctl auth login'")
	}
	httpClient := newHTTPClient(cfg)
	opts := options(cfg)
	return ssov1connect.NewUserAttributeMapperServiceClient(httpClient, cfg.ServerEndpoint, opts...), nil
}

// ProtocolMapperServiceClient returns a new ProtocolMapperService client.
func ProtocolMapperServiceClient(cfg *config.Context) (ssov1connect.ProtocolMapperServiceClient, error) {
	if cfg == nil || cfg.ServerEndpoint == "" {
		return nil, fmt.Errorf("invalid context or server endpoint for ProtocolMapperService client")
	}
	if cfg.UserAuthToken == "" {
		return nil, fmt.Errorf("user authentication token not found in current context. Please login using 'ssoctl auth login'")
	}
	httpClient := newHTTPClient(cfg)
	opts := options(cfg)
	return ssov1connect.NewProtocolMapperServiceClient(httpClient, cfg.ServerEndpoint, opts...), nil
}

// ClientScopeServiceClient returns a new ClientScopeService client.
func ClientScopeServiceClient(cfg *config.Context) (ssov1connect.ClientScopeServiceClient, error) {
	if cfg == nil || cfg.ServerEndpoint == "" {
		return nil, fmt.Errorf("invalid context or server endpoint for ClientScopeService client")
	}
	if cfg.UserAuthToken == "" {
		return nil, fmt.Errorf("user authentication token not found in current context. Please login using 'ssoctl auth login'")
	}
	httpClient := newHTTPClient(cfg)
	opts := options(cfg)
	return ssov1connect.NewClientScopeServiceClient(httpClient, cfg.ServerEndpoint, opts...), nil
}

// OIDCConfigurationServiceClient returns a new OIDCConfigurationService client.
func OIDCConfigurationServiceClient(cfg *config.Context) (ssov1connect.OIDCConfigurationServiceClient, error) {
	if cfg == nil || cfg.ServerEndpoint == "" {
		return nil, fmt.Errorf("invalid context or server endpoint for OIDCConfigurationService client")
	}
	if cfg.UserAuthToken == "" {
		return nil, fmt.Errorf("user authentication token not found in current context. Please login using 'ssoctl auth login'")
	}
	httpClient := newHTTPClient(cfg)
	opts := options(cfg)
	return ssov1connect.NewOIDCConfigurationServiceClient(httpClient, cfg.ServerEndpoint, opts...), nil
}

// authInterceptor is a simple client interceptor to add the auth token.
type authInterceptor struct {
	token string
}

func (i *authInterceptor) WrapUnary(next connect.UnaryFunc) connect.UnaryFunc {
	return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
		// Check if it's safe to set header (e.g. not already set, or specific procedures)
		// For this simple case, always set it.
		req.Header().Set("Authorization", "Bearer "+i.token)
		return next(ctx, req)
	}
}

func (i *authInterceptor) WrapStreamingClient(next connect.StreamingClientFunc) connect.StreamingClientFunc {
	return func(ctx context.Context, spec connect.Spec) connect.StreamingClientConn {
		conn := next(ctx, spec)
		conn.RequestHeader().Set("Authorization", "Bearer "+i.token)
		return conn
	}
}

func (i *authInterceptor) WrapStreamingHandler(next connect.StreamingHandlerFunc) connect.StreamingHandlerFunc {
	// Not used for client interceptor, just pass through.
	return next
}

// Ensure authInterceptor implements connect.Interceptor
var _ connect.Interceptor = (*authInterceptor)(nil)
