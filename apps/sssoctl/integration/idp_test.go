package integration

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCLIIdP_Add_OIDC(t *testing.T) {
	h := SetupCLITest(t)
	defer h.Close()

	out, err := h.ExecuteCommand(
		"idp", "add",
		"--name", "test-oidc",
		"--type", "OIDC",
		"--oidc-issuer-url", "https://accounts.google.com",
		"--oidc-client-id", "test-client-id",
	)
	require.NoError(t, err, "idp add: %s", out)
	assert.Contains(t, out, "IdP configuration added successfully")

	parsed := parseYAMLOutput(t, out)
	id, ok := parsed["id"].(string)
	require.True(t, ok, "id not found in output")
	require.NotEmpty(t, id, "id is empty")
	assert.Equal(t, "test-oidc", parsed["name"])
	t.Logf("created IdP: %s", id)
}

func TestCLIIdP_Get(t *testing.T) {
	h := SetupCLITest(t)
	defer h.Close()

	addOut, err := h.ExecuteCommand(
		"idp", "add",
		"--name", "get-test-oidc",
		"--type", "OIDC",
		"--oidc-issuer-url", "https://accounts.google.com",
		"--oidc-client-id", "get-test-client-id",
	)
	require.NoError(t, err, "idp add: %s", addOut)

	addParsed := parseYAMLOutput(t, addOut)
	idpID := addParsed["id"].(string)

	getOut, err := h.ExecuteCommand("idp", "get", idpID)
	require.NoError(t, err, "idp get: %s", getOut)
	assert.Contains(t, getOut, "get-test-oidc", "output should contain IdP name")
	assert.Contains(t, getOut, idpID, "output should contain IdP ID")
	assert.NotContains(t, getOut, "client_secret", "client_secret should NOT be in output")
}

func TestCLIIdP_List(t *testing.T) {
	h := SetupCLITest(t)
	defer h.Close()

	for _, name := range []string{"list-test-a", "list-test-b"} {
		_, err := h.ExecuteCommand(
			"idp", "add",
			"--name", name,
			"--type", "OIDC",
			"--oidc-issuer-url", "https://accounts.google.com",
			"--oidc-client-id", name+"-client-id",
		)
		require.NoError(t, err, "idp add %s", name)
	}

	listOut, err := h.ExecuteCommand("idp", "list")
	require.NoError(t, err, "idp list: %s", listOut)
	assert.Contains(t, listOut, "list-test-a", "output should contain first IdP")
	assert.Contains(t, listOut, "list-test-b", "output should contain second IdP")
}

func TestCLIIdP_Update(t *testing.T) {
	h := SetupCLITest(t)
	defer h.Close()

	addOut, err := h.ExecuteCommand(
		"idp", "add",
		"--name", "update-test-oidc",
		"--type", "OIDC",
		"--oidc-issuer-url", "https://accounts.google.com",
		"--oidc-client-id", "update-test-client-id",
	)
	require.NoError(t, err, "idp add: %s", addOut)

	addParsed := parseYAMLOutput(t, addOut)
	idpID := addParsed["id"].(string)

	updOut, err := h.ExecuteCommand(
		"idp", "update", idpID,
		"--name", "updated-idp",
		"--enabled=false",
	)
	require.NoError(t, err, "idp update: %s", updOut)
	assert.Contains(t, updOut, "IdP configuration updated successfully")
	assert.Contains(t, updOut, "updated-idp", "output should contain updated name")
}

func TestCLIIdP_Delete(t *testing.T) {
	h := SetupCLITest(t)
	defer h.Close()

	addOut, err := h.ExecuteCommand(
		"idp", "add",
		"--name", "delete-test-oidc",
		"--type", "OIDC",
		"--oidc-issuer-url", "https://accounts.google.com",
		"--oidc-client-id", "delete-test-client-id",
	)
	require.NoError(t, err, "idp add: %s", addOut)

	addParsed := parseYAMLOutput(t, addOut)
	idpID := addParsed["id"].(string)

	delOut, err := h.ExecuteCommand("idp", "delete", idpID)
	require.NoError(t, err, "idp delete: %s", delOut)
	assert.Contains(t, delOut, "deleted successfully")
}

func TestCLIIdP_Add_OIDC_MissingFields(t *testing.T) {
	h := SetupCLITest(t)
	defer h.Close()

	out, err := h.ExecuteCommand(
		"idp", "add",
		"--name", "test",
		"--type", "OIDC",
	)
	assert.Error(t, err, "expected error for missing OIDC fields")

	errMsg := strings.ToLower(out)
	hasIssuerHint := strings.Contains(errMsg, "--oidc-issuer-url")
	hasClientHint := strings.Contains(errMsg, "--oidc-client-id")
	assert.True(t, hasIssuerHint || hasClientHint,
		"error should mention --oidc-issuer-url or --oidc-client-id: %s", out)
}
