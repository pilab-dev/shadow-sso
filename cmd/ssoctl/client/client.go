package client

import (
	"context"
	// "crypto/tls" // Only if TLSClientConfig is actually used
	"fmt"
	"net/http"

	"connectrpc.com/connect"
	"github.com/pilab-dev/shadow-sso/cmd/ssoctl/config"
	"github.com/pilab-dev/shadow-sso/gen/proto/sso/v1/ssov1connect"
)

// AuthServiceClient returns a new AuthService client.
func AuthServiceClient(cfg *config.Context) (ssov1connect.AuthServiceClient, error) {
	if cfg == nil || cfg.ServerEndpoint == "" {
		return nil, fmt.Errorf("invalid context or server endpoint for AuthService client")
	}
	httpClient := &http.Client{
		// For development, allow insecure connections if endpoint is not HTTPS.
		// For production, ensure TLS. Transport can be configured here.
		// Example for local dev if server is HTTP only:
		// Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
		// However, for h2c (HTTP/2 Cleartext), no special TLS config is needed for the client if server supports it.
		// If server is HTTPS, http.DefaultClient or a client with proper TLS config should be used.
	}
	opts := []connect.ClientOption{
		connect.WithProtoJSON(), // Use JSON, can also use connect.WithProtoBinary()
	}
	// If token is present, add an interceptor to set Authorization header.
	if cfg.UserAuthToken != "" {
		opts = append(opts, connect.WithInterceptors(&authInterceptor{token: cfg.UserAuthToken}))
	}

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
	httpClient := &http.Client{ /* Consider sharing httpClient or transport config if used across clients */ }
	opts := []connect.ClientOption{
		connect.WithProtoJSON(),
		connect.WithInterceptors(&authInterceptor{token: cfg.UserAuthToken}), // Always add auth for UserService
	}
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
	httpClient := &http.Client{ /* ... consider shared transport ... */ }
	opts := []connect.ClientOption{
		connect.WithProtoJSON(),
		connect.WithInterceptors(&authInterceptor{token: cfg.UserAuthToken}),
	}
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
	httpClient := &http.Client{ /* ... consider shared transport ... */ }
	opts := []connect.ClientOption{
		connect.WithProtoJSON(),
		connect.WithInterceptors(&authInterceptor{token: cfg.UserAuthToken}),
	}
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
	httpClient := &http.Client{ /* ... consider shared transport ... */ }
	opts := []connect.ClientOption{
		connect.WithProtoJSON(),
		connect.WithInterceptors(&authInterceptor{token: cfg.UserAuthToken}),
	}
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
	httpClient := &http.Client{ /* ... consider shared transport ... */ }
	opts := []connect.ClientOption{
		connect.WithProtoJSON(),
		connect.WithInterceptors(&authInterceptor{token: cfg.UserAuthToken}),
	}
	return ssov1connect.NewTwoFactorServiceClient(httpClient, cfg.ServerEndpoint, opts...), nil
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
