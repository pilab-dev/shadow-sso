package integration

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// parseSAKeyJSON extracts the private_key_id from a service account key JSON output.
func parseSAKeyJSON(t testing.TB, output string) map[string]string {
	t.Helper()
	var result map[string]string
	err := json.Unmarshal([]byte(output), &result)
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
	assert.Equal(t, "SERVICE_ACCOUNT", parsed["type"], "type should be SERVICE_ACCOUNT")
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

	// Extract SA ID from stderr (printed after JSON: "Service Account ID: <id>")
	// The SA ID is printed to stderr, so get it from the JSON instead
	parsed := parseSAKeyJSON(t, createOut)
	saID := parsed["client_id"]
	require.NotEmpty(t, saID, "client_id should be in JSON output")

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
	saID := parsed["client_id"]
	keyID := parsed["private_key_id"]
	require.NotEmpty(t, saID, "client_id should be in JSON output")
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

	_, err := h.ExecuteCommand("service-account", "create-key")
	require.Error(t, err, "should fail without --project-id")
	assert.Contains(t, err.Error(), "project-id is required", "error should mention missing --project-id")
}
