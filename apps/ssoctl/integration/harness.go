package integration

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"connectrpc.com/connect"
	sssoint "github.com/pilab-dev/shadow-sso/apps/ssso/integration"
	"github.com/pilab-dev/shadow-sso/apps/ssso/config"
	"github.com/pilab-dev/shadow-sso/domain"
	ssov1 "github.com/pilab-dev/shadow-sso/gen/proto/sso/v1"
	"github.com/pilab-dev/shadow-sso/gen/proto/sso/v1/ssov1connect"
	pkgauth "github.com/pilab-dev/shadow-sso/pkg/auth"
	"github.com/pilab-dev/shadow-sso/services"
	"golang.org/x/crypto/bcrypt"
)

// CLITestHarness provides a fully-initialized SSO test server with an admin
// token, plus gRPC clients for testing ssoctl CLI command equivalents.
type CLITestHarness struct {
	Server       *http.Server
	RepoProvider services.RepositoryProvider
	ServerAddr   string
	AdminToken   string

	AuthClient ssov1connect.AuthServiceClient
	SAClient   ssov1connect.ServiceAccountServiceClient
	IdPClient  ssov1connect.IdPManagementServiceClient
}

// SetupCLITest starts an SSO test server with admin bootstrap, logs in as
// admin, and returns a harness with pre-configured gRPC clients.
func SetupCLITest(t testing.TB) *CLITestHarness {
	t.Helper()

	// Start SSO server with admin bootstrap
	srv, provider, addr := sssoint.StartTestServer(t, func(cfg *config.Config) {
		cfg.InitialAdminEnabled = true
		cfg.InitialAdminEmail = "admin@test.com"
		cfg.InitialAdminPassword = "test-password-123!"
		cfg.InitialAdminFirstName = "Admin"
		cfg.InitialAdminLastName = "User"
	})
	if srv == nil {
		t.Skip("SSO test server not available (MongoDB down?)")
		return nil
	}

	// Bootstrap the admin user in MongoDB (StartTestServer does not do this automatically)
	bootstrapAdminUser(t, provider, "admin@test.com", "test-password-123!", "Admin", "User")

	httpClient := &http.Client{}

	// Login as admin
	authClient := ssov1connect.NewAuthServiceClient(httpClient, addr, connect.WithProtoJSON())
	loginResp, err := authClient.Login(context.Background(), connect.NewRequest(&ssov1.LoginRequest{
		Email:    "admin@test.com",
		Password: "test-password-123!",
	}))
	if err != nil {
		sssoint.StopTestServer(t, srv, provider)
		t.Fatalf("Admin login failed: %v", err)
		return nil
	}
	adminToken := loginResp.Msg.AccessToken

	// Build authenticated gRPC clients
	authOpts := []connect.ClientOption{
		connect.WithProtoJSON(),
		connect.WithInterceptors(&authHeaderInterceptor{token: adminToken}),
	}

	h := &CLITestHarness{
		Server:       srv,
		RepoProvider: provider,
		ServerAddr:   addr,
		AdminToken:   adminToken,
		AuthClient:   authClient,
		SAClient:     ssov1connect.NewServiceAccountServiceClient(httpClient, addr, authOpts...),
		IdPClient:    ssov1connect.NewIdPManagementServiceClient(httpClient, addr, authOpts...),
	}

	return h
}

// StopCLITest tears down the test server and MongoDB connection.
func StopCLITest(t testing.TB, h *CLITestHarness) {
	t.Helper()
	if h == nil {
		return
	}
	sssoint.StopTestServer(t, h.Server, h.RepoProvider)
}

// authHeaderInterceptor injects a Bearer token into outgoing gRPC requests.
type authHeaderInterceptor struct {
	token string
}

func (i *authHeaderInterceptor) WrapUnary(next connect.UnaryFunc) connect.UnaryFunc {
	return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
		req.Header().Set("Authorization", "Bearer "+i.token)
		return next(ctx, req)
	}
}

func (i *authHeaderInterceptor) WrapStreamingClient(next connect.StreamingClientFunc) connect.StreamingClientFunc {
	return func(ctx context.Context, spec connect.Spec) connect.StreamingClientConn {
		conn := next(ctx, spec)
		conn.RequestHeader().Set("Authorization", "Bearer "+i.token)
		return conn
	}
}

func (i *authHeaderInterceptor) WrapStreamingHandler(next connect.StreamingHandlerFunc) connect.StreamingHandlerFunc {
	return next
}

var _ connect.Interceptor = (*authHeaderInterceptor)(nil)

// bootstrapAdminUser creates the initial admin user if it does not exist,
// replicating the bootstrap logic from apps/ssso/integration/bootstrap_test.go.
func bootstrapAdminUser(t testing.TB, provider services.RepositoryProvider, email, password, firstName, lastName string) {
	t.Helper()
	ctx := context.Background()
	userRepo := provider.UserRepository(ctx)

	_, uErr := userRepo.GetUserByEmail(ctx, email)
	if errors.Is(uErr, domain.ErrUserNotFound) {
		hasher := pkgauth.NewBcryptPasswordHasher(bcrypt.DefaultCost)
		hash, pHashErr := hasher.Hash(password)
		if pHashErr != nil {
			t.Fatalf("Failed to hash initial admin password: %v", pHashErr)
			return
		}
		user := &domain.User{
			Email:        email,
			PasswordHash: hash,
			FirstName:    firstName,
			LastName:     lastName,
			Status:       domain.UserStatusActive,
			Roles:        []string{"ROLE_ADMIN"},
		}
		if cErr := userRepo.CreateUser(ctx, user); cErr != nil {
			t.Fatalf("Failed to create initial admin user: %v", cErr)
		}
	} else if uErr != nil {
		t.Fatalf("Failed to check for existing admin user: %v", uErr)
	}
}
