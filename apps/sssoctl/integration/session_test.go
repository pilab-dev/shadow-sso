package integration

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestCLISession_List(t *testing.T) {
	h := SetupCLITest(t)
	defer h.Close()

	out, err := h.ExecuteCommand("session", "list")
	require.NoError(t, err, "session list: %s", out)
	assert.NotContains(t, out, "No active sessions found",
		"expected active sessions after login")
	t.Logf("sessions:\n%s", out)
}

func TestCLISession_Clear(t *testing.T) {
	h := SetupCLITest(t)
	defer h.Close()

	listOut, _ := h.ExecuteCommand("session", "list")
	if strings.Contains(listOut, "No active sessions found") {
		t.Skip("no sessions to clear")
	}

	clearOut, err := h.ExecuteCommand("session", "clear", "--all")
	require.NoError(t, err, "session clear --all: %s", clearOut)
	assert.Contains(t, clearOut, "cleared successfully")
}

func TestCLISession_Clear_NoSessions(t *testing.T) {
	h := SetupCLITest(t)
	defer h.Close()

	// Save current config
	origData, err := os.ReadFile(h.ConfigFile())
	require.NoError(t, err, "failed to read config")

	// Write config without token
	noAuthCfg := cliConfig{
		CurrentContext: "test",
		Contexts: map[string]cliContext{
			"test": {
				Name:           "test",
				ServerEndpoint: h.ServerAddr(),
			},
		},
	}
	noAuthData, err := yaml.Marshal(noAuthCfg)
	require.NoError(t, err, "failed to marshal no-auth config")
	require.NoError(t, os.WriteFile(h.ConfigFile(), noAuthData, 0644))

	// Run session clear without auth via a separate binary invocation
	// (h.ExecuteCommand prepends --config, but we need the no-auth config already in place)
	out, err := h.ExecuteCommand("session", "clear", "--all")

	// Restore original config
	os.WriteFile(h.ConfigFile(), origData, 0644)

	assert.Error(t, err, "expected error when clearing sessions without auth")
	t.Logf("no-auth clear output:\n%s", out)
}
