package integration

import (
	"context"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	ssov1 "github.com/pilab-dev/shadow-sso/gen/proto/sso/v1"
	"github.com/pilab-dev/shadow-sso/gen/proto/sso/v1/ssov1connect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCLIAuth_Login_Success(t *testing.T) {
	h := SetupCLITest(t)
	defer h.Close()

	token := h.AdminToken()
	assert.NotEmpty(t, token, "admin token should be set after login")

	data, err := os.ReadFile(h.ConfigFile())
	require.NoError(t, err)
	assert.Contains(t, string(data), "user_auth_token", "config should contain token")
	assert.Contains(t, string(data), token[:10], "config should contain admin token")
}

func TestCLIAuth_Login_WrongPassword(t *testing.T) {
	h := SetupCLITest(t)
	defer h.Close()

	authClient := ssov1connect.NewAuthServiceClient(
		&http.Client{Timeout: 10 * time.Second},
		h.ServerAddr(),
		connect.WithProtoJSON(),
	)

	_, err := authClient.Login(context.Background(), connect.NewRequest(&ssov1.LoginRequest{
		Email:    defaultAdminEmail,
		Password: "WrongPass999!",
	}))
	require.Error(t, err, "login with wrong password should fail")
	errStr := err.Error()
	assert.True(t,
		strings.Contains(errStr, "invalid email or password") ||
			strings.Contains(errStr, "unauthenticated"),
		"error should indicate auth failure: %v", err)
}

func TestCLIAuth_Login_NoServer(t *testing.T) {
	authClient := ssov1connect.NewAuthServiceClient(
		&http.Client{Timeout: 2 * time.Second},
		"http://127.0.0.1:19999",
		connect.WithProtoJSON(),
	)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, err := authClient.Login(ctx, connect.NewRequest(&ssov1.LoginRequest{
		Email:    "user@example.com",
		Password: "password",
	}))
	require.Error(t, err, "login to bad endpoint should fail")
	errStr := err.Error()
	assert.True(t,
		strings.Contains(errStr, "connection refused") ||
			strings.Contains(errStr, "unavailable") ||
			strings.Contains(errStr, "deadline"),
		"error should indicate connection failure: %v", err)
}

func TestCLIAuth_Logout_Success(t *testing.T) {
	h := SetupCLITest(t)
	defer h.Close()

	token := h.AdminToken()
	require.NotEmpty(t, token, "token should exist before logout")

	configData, err := os.ReadFile(h.ConfigFile())
	require.NoError(t, err)
	assert.Contains(t, string(configData), "user_auth_token")

	out, logoutErr := h.ExecuteCommand("auth", "logout")
	require.NoError(t, logoutErr, "logout should succeed, output: %s", out)
	assert.Contains(t, out, "Logged out successfully")

	configData, err = os.ReadFile(h.ConfigFile())
	require.NoError(t, err)
	assert.NotContains(t, string(configData), "user_auth_token",
		"token should be cleared from config after logout")
}

func TestCLIAuth_Logout_NotLoggedIn(t *testing.T) {
	root := SetupConfigTest(t)

	_, err := ExecuteCommand(t, root, "config", "set-context", "test",
		"--server", "http://localhost:19999")
	require.NoError(t, err, "set-context should succeed")

	out, err := ExecuteCommand(t, root, "auth", "logout")
	require.NoError(t, err, "logout without login should not error")
	assert.Contains(t, out, "Not logged in")
}

var _ = http.DefaultClient
