package integration

import (
	"context"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/pilab-dev/shadow-sso/apps/ssso/config"
	sssoint "github.com/pilab-dev/shadow-sso/apps/ssso/integration"
	"github.com/pilab-dev/shadow-sso/domain"
	pkgauth "github.com/pilab-dev/shadow-sso/pkg/auth"
	"github.com/pilab-dev/shadow-sso/services"
	ssov1 "github.com/pilab-dev/shadow-sso/gen/proto/sso/v1"
	"github.com/pilab-dev/shadow-sso/gen/proto/sso/v1/ssov1connect"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
	"gopkg.in/yaml.v3"
)

const (
	defaultAdminEmail    = "admin@integration.test"
	defaultAdminPassword = "StrongP@ssw0rd!123"
)

type CLIHarness struct {
	t             testing.TB
	srv           *http.Server
	provider      services.RepositoryProvider
	serverAddr    string
	tmpDir        string
	configFile    string
	cliBin        string
	adminEmail    string
	adminPassword string
	adminToken    string
}

func SetupCLITest(t *testing.T) *CLIHarness {
	return SetupCLITestWithCredentials(t, defaultAdminEmail, defaultAdminPassword)
}

func SetupCLITestWithCredentials(t testing.TB, adminEmail, adminPassword string) *CLIHarness {
	t.Helper()

	srv, provider, addr := sssoint.StartTestServer(t, func(cfg *config.Config) {
		cfg.LogLevel = "error"
	})
	if srv == nil {
		t.Fatal("failed to start test server (MongoDB likely unavailable)")
	}

	userRepo := provider.UserRepository(context.Background())
	passwordHasher := pkgauth.NewBcryptPasswordHasher(bcrypt.DefaultCost)
	hash, err := passwordHasher.Hash(adminPassword)
	require.NoError(t, err, "failed to hash admin password")

	adminUser := &domain.User{
		Email:        adminEmail,
		PasswordHash: hash,
		FirstName:    "Admin",
		LastName:     "User",
		Status:       domain.UserStatusActive,
		Roles:        []string{"ROLE_ADMIN"},
	}
	require.NoError(t, userRepo.CreateUser(context.Background(), adminUser),
		"failed to create admin user")

	tmpDir := t.TempDir()
	cliBin := filepath.Join(tmpDir, "ssoctl")
	projectRoot := findProjectRoot(t)

	buildCmd := exec.Command("go", "build", "-o", cliBin, "./apps/sssoctl")
	buildCmd.Dir = projectRoot
	buildOut, buildErr := buildCmd.CombinedOutput()
	require.NoError(t, buildErr, "failed to build ssoctl: %s", string(buildOut))

	authClient := ssov1connect.NewAuthServiceClient(
		&http.Client{Timeout: 10 * time.Second},
		addr,
		connect.WithProtoJSON(),
	)

	resp, err := authClient.Login(context.Background(), connect.NewRequest(&ssov1.LoginRequest{
		Email:    adminEmail,
		Password: adminPassword,
	}))
	require.NoError(t, err, "admin login failed")
	require.NotNil(t, resp.Msg, "login response nil")
	require.NotEmpty(t, resp.Msg.AccessToken, "empty access token")

	adminToken := resp.Msg.AccessToken

	configFile := filepath.Join(tmpDir, "config.yaml")
	cfg := cliConfig{
		CurrentContext: "test",
		Contexts: map[string]cliContext{
			"test": {
				Name:           "test",
				ServerEndpoint: addr,
				UserAuthToken:  adminToken,
			},
		},
	}
	data, err := yaml.Marshal(cfg)
	require.NoError(t, err, "failed to marshal config")
	require.NoError(t, os.WriteFile(configFile, data, 0644), "failed to write config")

	return &CLIHarness{
		t:             t,
		srv:           srv,
		provider:      provider,
		serverAddr:    addr,
		tmpDir:        tmpDir,
		configFile:    configFile,
		cliBin:        cliBin,
		adminEmail:    adminEmail,
		adminPassword: adminPassword,
		adminToken:    adminToken,
	}
}

func (h *CLIHarness) ExecuteCommand(args ...string) (string, error) {
	h.t.Helper()
	fullArgs := append([]string{"--config", h.configFile}, args...)
	cmd := exec.Command(h.cliBin, fullArgs...)
	output, err := cmd.CombinedOutput()
	return string(output), err
}

func (h *CLIHarness) LoginAsUser(email, password string) {
	h.t.Helper()

	authClient := ssov1connect.NewAuthServiceClient(
		&http.Client{Timeout: 10 * time.Second},
		h.serverAddr,
		connect.WithProtoJSON(),
	)

	resp, err := authClient.Login(context.Background(), connect.NewRequest(&ssov1.LoginRequest{
		Email:    email,
		Password: password,
	}))
	require.NoError(h.t, err, "user login failed for %s", email)
	require.NotNil(h.t, resp.Msg, "login response nil for %s", email)
	require.NotEmpty(h.t, resp.Msg.AccessToken, "empty access token for %s", email)

	h.writeConfigWithToken(resp.Msg.AccessToken)
}

func (h *CLIHarness) RefreshAdminToken() {
	h.t.Helper()

	authClient := ssov1connect.NewAuthServiceClient(
		&http.Client{Timeout: 10 * time.Second},
		h.serverAddr,
		connect.WithProtoJSON(),
	)

	resp, err := authClient.Login(context.Background(), connect.NewRequest(&ssov1.LoginRequest{
		Email:    h.adminEmail,
		Password: h.adminPassword,
	}))
	require.NoError(h.t, err, "admin re-login failed")
	require.NotNil(h.t, resp.Msg, "login response nil")

	h.adminToken = resp.Msg.AccessToken
	h.writeConfigWithToken(resp.Msg.AccessToken)
}

func (h *CLIHarness) AdminToken() string {
	return h.adminToken
}

func (h *CLIHarness) ServerAddr() string {
	return h.serverAddr
}

func (h *CLIHarness) ConfigFile() string {
	return h.configFile
}

func (h *CLIHarness) Close() {
	if h.srv != nil && h.provider != nil {
		sssoint.StopTestServer(h.t, h.srv, h.provider)
	}
}

func (h *CLIHarness) writeConfigWithToken(token string) {
	cfg := cliConfig{
		CurrentContext: "test",
		Contexts: map[string]cliContext{
			"test": {
				Name:           "test",
				ServerEndpoint: h.serverAddr,
				UserAuthToken:  token,
			},
		},
	}
	data, err := yaml.Marshal(cfg)
	require.NoError(h.t, err, "failed to marshal config")
	require.NoError(h.t, os.WriteFile(h.configFile, data, 0644), "failed to write config")
}

type cliConfig struct {
	CurrentContext string                `yaml:"current_context"`
	Contexts       map[string]cliContext `yaml:"contexts"`
}

type cliContext struct {
	Name           string `yaml:"name"`
	ServerEndpoint string `yaml:"server_endpoint"`
	UserAuthToken  string `yaml:"user_auth_token,omitempty"`
}

func findProjectRoot(t testing.TB) string {
	t.Helper()
	dir, err := os.Getwd()
	require.NoError(t, err, "failed to get working directory")

	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			cliDir := filepath.Join(dir, "apps", "sssoctl")
			if info, err := os.Stat(cliDir); err == nil && info.IsDir() {
				return dir
			}
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("could not find project root with go.mod and apps/sssoctl")
			return ""
		}
		dir = parent
	}
}

var _ = os.DevNull
