package integration

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// parseSAKeyJSON extracts the service account key JSON from output that may
// contain stderr messages (e.g. "Using config file: ...") before the JSON.
func parseSAKeyJSON(t testing.TB, output string) map[string]string {
	t.Helper()
	// CombinedOutput() merges stdout+stderr; find the first '{' to locate JSON start.
	idx := strings.IndexByte(output, '{')
	require.GreaterOrEqual(t, idx, 0, "no JSON object found in output:\n%s", output)
	var result map[string]string
	err := json.Unmarshal([]byte(output[idx:]), &result)
	require.NoError(t, err, "failed to parse SA key JSON:\n%s", output)
	return result
}

// TestCLIServiceAccount_CreateKey creates a service account key and verifies JSON output.
func TestCLIServiceAccount_CreateKey(t *testing.T) {
	h := SetupCLITest(t)
	defer h.Close()

	out, err := h.ExecuteCommand(
		"service-account", "create-key",
		"--project-id", "test-project",
		"--display-name", "Test SA",
	)
	require.NoError(t, err, "SA create-key failed: %s", out)

	parsed := parseSAKeyJSON(t, out)
	assert.NotEmpty(t, parsed["private_key"], "output should contain private_key")
	assert.NotEmpty(t, parsed["private_key_id"], "output should contain private_key_id")
	assert.NotEmpty(t, parsed["client_email"], "output should contain client_email")
	assert.Equal(t, "test-project", parsed["project_id"], "project_id should match")
	assert.Equal(t, "service_account", parsed["type"], "type should be service_account")
	t.Logf("created SA key: %s", parsed["private_key_id"])
}

// TestCLIServiceAccount_ListKeys lists keys after creating one.
func TestCLIServiceAccount_ListKeys(t *testing.T) {
	h := SetupCLITest(t)
	defer h.Close()

	// Create a key first
	createOut, err := h.ExecuteCommand(
		"service-account", "create-key",
		"--project-id", "list-test-project",
		"--display-name", "List Test SA",
	)
	require.NoError(t, err, "SA create-key failed: %s", createOut)

	// The SA ID is now part of the JSON output as service_account_id.
	parsed := parseSAKeyJSON(t, createOut)
	saID := parsed["service_account_id"]
	require.NotEmpty(t, saID, "service_account_id should be in JSON output")

	// List keys
	listOut, err := h.ExecuteCommand("service-account", "list-keys", saID)
	require.NoError(t, err, "SA list-keys failed: %s", listOut)
	assert.NotContains(t, listOut, "No keys found", "list should return at least one key")
}

// TestCLIServiceAccount_DeleteKey creates a key then deletes it.
func TestCLIServiceAccount_DeleteKey(t *testing.T) {
	h := SetupCLITest(t)
	defer h.Close()

	// Create a key first
	createOut, err := h.ExecuteCommand(
		"service-account", "create-key",
		"--project-id", "delete-test-project",
		"--display-name", "Delete Test SA",
	)
	require.NoError(t, err, "SA create-key failed: %s", createOut)

	parsed := parseSAKeyJSON(t, createOut)
	saID := parsed["service_account_id"]
	keyID := parsed["private_key_id"]
	require.NotEmpty(t, saID, "service_account_id should be in JSON output")
	require.NotEmpty(t, keyID, "private_key_id should be in JSON output")

	// Delete the key
	delOut, err := h.ExecuteCommand("service-account", "delete-key", saID, keyID)
	require.NoError(t, err, "SA delete-key failed: %s", delOut)
	assert.Contains(t, delOut, "deleted successfully", "output should confirm deletion")
}

// TestCLIServiceAccount_CreateKey_MissingProject requires --project-id flag.
func TestCLIServiceAccount_CreateKey_MissingProject(t *testing.T) {
	h := SetupCLITest(t)
	defer h.Close()

	out, err := h.ExecuteCommand("service-account", "create-key")
	require.Error(t, err, "should fail without --project-id")
	assert.Contains(t, out, "project-id is required", "output should mention missing --project-id")
}
