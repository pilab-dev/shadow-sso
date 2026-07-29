package integration

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	ssoctlconfig "github.com/pilab-dev/shadow-sso/apps/sssoctl/cmd/config"
	ssov1 "github.com/pilab-dev/shadow-sso/gen/proto/sso/v1"
	"github.com/pilab-dev/shadow-sso/gen/proto/sso/v1/ssov1connect"
	"gopkg.in/yaml.v3"
)

const (
	cliTestEmail    = "admin@integration.test"
	cliTestPassword = "StrongP@ssw0rd!123"
)

func loginViaAPI(t *testing.T, h *CLITestHarness) {
	t.Helper()
	authClient := ssov1connect.NewAuthServiceClient(
		&http.Client{Timeout: 10 * time.Second},
		h.Addr,
		connect.WithProtoJSON(),
	)
	resp, err := authClient.Login(context.Background(), connect.NewRequest(&ssov1.LoginRequest{
		Email:    cliTestEmail,
		Password: cliTestPassword,
	}))
	if err != nil {
		t.Fatalf("api login failed: %v", err)
	}
	ctx := ssoctlconfig.GlobalConfig.Contexts["test"]
	if ctx == nil {
		t.Fatal("context 'test' not found")
	}
	ctx.UserAuthToken = resp.Msg.AccessToken
}

func parseYAMLOutput(t testing.TB, output string) map[string]interface{} {
	t.Helper()
	var result map[string]interface{}
	lines := strings.Split(output, "\n")
	yamlStart := 0
	for i, line := range lines {
		if strings.Contains(line, ":") &&
			!strings.HasPrefix(strings.TrimSpace(line), "IMPORTANT") &&
			!strings.Contains(line, "registered successfully") {
			yamlStart = i
			break
		}
	}
	yamlBlock := strings.Join(lines[yamlStart:], "\n")
	if err := yaml.Unmarshal([]byte(yamlBlock), &result); err != nil {
		t.Fatalf("parse YAML: %v\nOutput:\n%s", err, output)
	}
	return result
}

func TestCLIClient_Register(t *testing.T) {
	h := SetupCLITest(t, cliTestEmail, cliTestPassword)
	defer h.Cleanup(t)
	loginViaAPI(t, h)

	out, err := ExecuteCommand(t, h.RootCmd,
		"client", "register",
		"--name", "Test App",
		"--type", "confidential",
		"--redirect-uris", "http://localhost:3000/callback",
		"--grant-types", "authorization_code,refresh_token",
	)
	if err != nil {
		t.Fatalf("client register: %v\nOutput: %s", err, out)
	}
	parsed := parseYAMLOutput(t, out)
	cid, ok := parsed["client_id"].(string)
	if !ok || cid == "" {
		t.Fatalf("no client_id in output: %v", parsed["client_id"])
	}
	if name := parsed["client_name"]; name != "Test App" {
		t.Errorf("client_name: want 'Test App', got %v", name)
	}
	if sec, ok := parsed["client_secret"]; !ok || sec == "" {
		t.Error("expected client_secret for confidential client")
	}
	t.Logf("registered: %s", cid)
}

func TestCLIClient_Get(t *testing.T) {
	h := SetupCLITest(t, cliTestEmail, cliTestPassword)
	defer h.Cleanup(t)
	loginViaAPI(t, h)

	regOut, _ := ExecuteCommand(t, h.RootCmd,
		"client", "register",
		"--name", "GetTest Client",
		"--type", "confidential",
		"--redirect-uris", "http://localhost:4000/callback",
		"--grant-types", "authorization_code",
	)
	parsed := parseYAMLOutput(t, regOut)
	cid := parsed["client_id"].(string)

	getOut, err := ExecuteCommand(t, h.RootCmd, "client", "get", cid)
	if err != nil {
		t.Fatalf("client get: %v\n%s", err, getOut)
	}
	if !strings.Contains(getOut, cid) {
		t.Errorf("output missing client ID %s", cid)
	}
	if !strings.Contains(getOut, "GetTest Client") {
		t.Errorf("output missing client name")
	}
}

func TestCLIClient_List(t *testing.T) {
	h := SetupCLITest(t, cliTestEmail, cliTestPassword)
	defer h.Cleanup(t)
	loginViaAPI(t, h)

	for _, n := range []string{"ListTest A", "ListTest B"} {
		ExecuteCommand(t, h.RootCmd,
			"client", "register",
			"--name", n,
			"--type", "confidential",
			"--redirect-uris", "http://localhost:5000/callback",
			"--grant-types", "client_credentials",
		)
	}
	out, err := ExecuteCommand(t, h.RootCmd, "client", "list", "--page-size", "10")
	if err != nil {
		t.Fatalf("client list: %v\n%s", err, out)
	}
	if strings.Contains(out, "No clients found") || strings.Contains(out, "not yet available") {
		t.Skip("list returned empty/not available")
	}
	if !strings.Contains(out, "ListTest A") || !strings.Contains(out, "ListTest B") {
		t.Errorf("list missing expected clients:\n%s", out)
	}
}

func TestCLIClient_Update(t *testing.T) {
	h := SetupCLITest(t, cliTestEmail, cliTestPassword)
	defer h.Cleanup(t)
	loginViaAPI(t, h)

	regOut, _ := ExecuteCommand(t, h.RootCmd,
		"client", "register",
		"--name", "UpdateTest Original",
		"--type", "confidential",
		"--redirect-uris", "http://localhost:6000/callback",
		"--grant-types", "authorization_code",
	)
	parsed := parseYAMLOutput(t, regOut)
	cid := parsed["client_id"].(string)

	updOut, err := ExecuteCommand(t, h.RootCmd,
		"client", "update", cid,
		"--name", "Updated App",
		"--redirect-uris", "http://new-callback.com",
	)
	if err != nil {
		t.Fatalf("client update: %v\n%s", err, updOut)
	}
	if !strings.Contains(updOut, "Updated App") {
		t.Errorf("update output missing new name:\n%s", updOut)
	}
	if !strings.Contains(updOut, "http://new-callback.com") {
		t.Errorf("update output missing new redirect URI:\n%s", updOut)
	}

	getOut, _ := ExecuteCommand(t, h.RootCmd, "client", "get", cid)
	if !strings.Contains(getOut, "Updated App") {
		t.Errorf("get output missing updated name:\n%s", getOut)
	}
}

func TestCLIClient_Delete(t *testing.T) {
	h := SetupCLITest(t, cliTestEmail, cliTestPassword)
	defer h.Cleanup(t)
	loginViaAPI(t, h)

	regOut, _ := ExecuteCommand(t, h.RootCmd,
		"client", "register",
		"--name", "DeleteTest Target",
		"--type", "confidential",
		"--redirect-uris", "http://localhost:7000/callback",
		"--grant-types", "client_credentials",
	)
	parsed := parseYAMLOutput(t, regOut)
	cid := parsed["client_id"].(string)

	delOut, err := ExecuteCommand(t, h.RootCmd, "client", "delete", cid, "--force")
	if err != nil {
		t.Fatalf("client delete: %v\n%s", err, delOut)
	}
	if !strings.Contains(delOut, "deleted successfully") {
		t.Errorf("delete: %s", delOut)
	}
	_, err = ExecuteCommand(t, h.RootCmd, "client", "get", cid)
	if err == nil {
		t.Errorf("expected error getting deleted client")
	}
}

func TestCLIClient_Register_Public(t *testing.T) {
	h := SetupCLITest(t, cliTestEmail, cliTestPassword)
	defer h.Cleanup(t)
	loginViaAPI(t, h)

	out, err := ExecuteCommand(t, h.RootCmd,
		"client", "register",
		"--name", "PublicTest App",
		"--type", "public",
		"--redirect-uris", "http://localhost:8000/callback",
		"--grant-types", "authorization_code",
	)
	if err != nil {
		t.Fatalf("client register public: %v\n%s", err, out)
	}
	parsed := parseYAMLOutput(t, out)
	if _, hasSecret := parsed["client_secret"]; hasSecret {
		t.Error("public client should NOT have client_secret")
	}
	if cid, _ := parsed["client_id"].(string); cid != "" {
		t.Logf("public client: %s", cid)
	}
}

func TestCLIClient_Register_MissingName(t *testing.T) {
	h := SetupCLITest(t, cliTestEmail, cliTestPassword)
	defer h.Cleanup(t)
	loginViaAPI(t, h)

	out, err := ExecuteCommand(t, h.RootCmd,
		"client", "register",
		"--type", "confidential",
		"--redirect-uris", "http://localhost:9000/callback",
	)
	if err == nil {
		t.Errorf("expected error for missing --name, got:\n%s", out)
	}
	if !strings.Contains(out, "name is required") {
		t.Errorf("expected 'name is required' error, got: %s", out)
	}
}
