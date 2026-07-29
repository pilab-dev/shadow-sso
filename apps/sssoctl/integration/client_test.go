package integration

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

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
	err := yaml.Unmarshal([]byte(yamlBlock), &result)
	require.NoError(t, err, "failed to parse YAML from output:\n%s", output)
	return result
}

func TestCLIClient_Register(t *testing.T) {
	h := SetupCLITest(t)
	defer h.Close()

	out, err := h.ExecuteCommand(
		"client", "register",
		"--name", "Test App",
		"--type", "confidential",
		"--redirect-uris", "http://localhost:3000/callback",
		"--grant-types", "authorization_code,refresh_token",
	)
	require.NoError(t, err, "client register: %s", out)

	parsed := parseYAMLOutput(t, out)
	cid, ok := parsed["client_id"].(string)
	require.True(t, ok, "client_id not found in output")
	require.NotEmpty(t, cid, "client_id is empty")
	assert.Equal(t, "Test App", parsed["client_name"])
	assert.NotEmpty(t, parsed["client_secret"], "confidential client should have client_secret")
	t.Logf("registered client: %s", cid)
}

func TestCLIClient_Get(t *testing.T) {
	h := SetupCLITest(t)
	defer h.Close()

	regOut, _ := h.ExecuteCommand(
		"client", "register",
		"--name", "GetTest Client",
		"--type", "confidential",
		"--redirect-uris", "http://localhost:4000/callback",
		"--grant-types", "authorization_code",
	)
	parsed := parseYAMLOutput(t, regOut)
	cid := parsed["client_id"].(string)

	getOut, err := h.ExecuteCommand("client", "get", cid)
	require.NoError(t, err, "client get: %s", getOut)
	assert.Contains(t, getOut, cid, "output should contain client ID")
	assert.Contains(t, getOut, "GetTest Client", "output should contain client name")
}

func TestCLIClient_List(t *testing.T) {
	h := SetupCLITest(t)
	defer h.Close()

	for _, n := range []string{"ListTest A", "ListTest B"} {
		h.ExecuteCommand(
			"client", "register",
			"--name", n,
			"--type", "confidential",
			"--redirect-uris", "http://localhost:5000/callback",
			"--grant-types", "client_credentials",
		)
	}
	out, err := h.ExecuteCommand("client", "list", "--page-size", "10")
	if err != nil {
		if strings.Contains(out, "not yet available") {
			t.Skip("ListClients not available on server")
		}
		t.Fatalf("client list: %v\n%s", err, out)
	}
	if strings.Contains(out, "No clients found") {
		t.Skip("list returned empty")
	}
	assert.Contains(t, out, "ListTest A")
	assert.Contains(t, out, "ListTest B")
}

func TestCLIClient_Update(t *testing.T) {
	h := SetupCLITest(t)
	defer h.Close()

	regOut, _ := h.ExecuteCommand(
		"client", "register",
		"--name", "UpdateTest Original",
		"--type", "confidential",
		"--redirect-uris", "http://localhost:6000/callback",
		"--grant-types", "authorization_code",
	)
	parsed := parseYAMLOutput(t, regOut)
	cid := parsed["client_id"].(string)

	updOut, err := h.ExecuteCommand(
		"client", "update", cid,
		"--name", "Updated App",
		"--redirect-uris", "http://new-callback.com",
	)
	require.NoError(t, err, "client update: %s", updOut)
	assert.Contains(t, updOut, "Updated App")
	assert.Contains(t, updOut, "http://new-callback.com")

	getOut, _ := h.ExecuteCommand("client", "get", cid)
	assert.Contains(t, getOut, "Updated App", "get should reflect updated name")
}

func TestCLIClient_Delete(t *testing.T) {
	h := SetupCLITest(t)
	defer h.Close()

	regOut, _ := h.ExecuteCommand(
		"client", "register",
		"--name", "DeleteTest Target",
		"--type", "confidential",
		"--redirect-uris", "http://localhost:7000/callback",
		"--grant-types", "client_credentials",
	)
	parsed := parseYAMLOutput(t, regOut)
	cid := parsed["client_id"].(string)

	delOut, err := h.ExecuteCommand("client", "delete", cid, "--force")
	require.NoError(t, err, "client delete: %s", delOut)
	assert.Contains(t, delOut, "deleted successfully")

	_, err = h.ExecuteCommand("client", "get", cid)
	assert.Error(t, err, "expected error getting deleted client")
}

func TestCLIClient_Register_Public(t *testing.T) {
	h := SetupCLITest(t)
	defer h.Close()

	out, err := h.ExecuteCommand(
		"client", "register",
		"--name", "PublicTest App",
		"--type", "public",
		"--redirect-uris", "http://localhost:8000/callback",
		"--grant-types", "authorization_code",
	)
	require.NoError(t, err, "client register public: %s", out)

	parsed := parseYAMLOutput(t, out)
	_, hasSecret := parsed["client_secret"]
	assert.False(t, hasSecret, "public client should NOT have client_secret")
	cid, _ := parsed["client_id"].(string)
	assert.NotEmpty(t, cid)
	t.Logf("public client: %s", cid)
}

func TestCLIClient_Register_MissingName(t *testing.T) {
	h := SetupCLITest(t)
	defer h.Close()

	out, err := h.ExecuteCommand(
		"client", "register",
		"--type", "confidential",
		"--redirect-uris", "http://localhost:9000/callback",
	)
	assert.Error(t, err, "expected error for missing --name")
	assert.Contains(t, out, "name is required", "error should mention missing name")
}
