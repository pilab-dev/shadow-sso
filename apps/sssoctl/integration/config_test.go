package integration

import (
	"os"
	"testing"

	"github.com/pilab-dev/shadow-sso/apps/sssoctl/cmd/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestCLIConfig_SetContext(t *testing.T) {
	root := SetupConfigTest(t)

	out, err := ExecuteCommand(t, root, "config", "set-context", "myctx", "--server", "http://localhost:8080")
	require.NoError(t, err, "set-context should succeed, got: %s", out)
	assert.Contains(t, out, "Context \"myctx\" created/modified.")

	data, err := os.ReadFile(ConfigFilePath(t))
	require.NoError(t, err, "config file should exist")

	var parsed struct {
		CurrentContext string `yaml:"current_context"`
		Contexts       map[string]struct {
			Name           string `yaml:"name"`
			ServerEndpoint string `yaml:"server_endpoint"`
		} `yaml:"contexts"`
	}
	err = yaml.Unmarshal(data, &parsed)
	require.NoError(t, err, "config file should be valid YAML")

	assert.Equal(t, "myctx", parsed.CurrentContext)
	ctx, ok := parsed.Contexts["myctx"]
	require.True(t, ok, "contexts should contain 'myctx'")
	assert.Equal(t, "http://localhost:8080", ctx.ServerEndpoint)
}

func TestCLIConfig_SetContext_Overwrite(t *testing.T) {
	root := SetupConfigTest(t)

	WriteConfigFile(t, configFileData{
		CurrentContext: "myctx",
		Contexts: map[string]contextFileCtx{
			"myctx": {Name: "myctx", ServerEndpoint: "http://localhost:8080"},
		},
	})

	out, err := ExecuteCommand(t, root, "config", "set-context", "myctx", "--server", "http://localhost:9090")
	require.NoError(t, err, "set-context overwrite should succeed, got: %s", out)
	assert.Contains(t, out, "Context \"myctx\" created/modified.")

	require.NotNil(t, config.GlobalConfig)
	require.Contains(t, config.GlobalConfig.Contexts, "myctx")
	assert.Equal(t, "http://localhost:9090", config.GlobalConfig.Contexts["myctx"].ServerEndpoint)
}

func TestCLIConfig_UseContext(t *testing.T) {
	root := SetupConfigTest(t)

	WriteConfigFile(t, configFileData{
		CurrentContext: "ctx1",
		Contexts: map[string]contextFileCtx{
			"ctx1": {Name: "ctx1", ServerEndpoint: "http://localhost:8080"},
			"ctx2": {Name: "ctx2", ServerEndpoint: "http://localhost:9090"},
		},
	})

	out, err := ExecuteCommand(t, root, "config", "use-context", "ctx2")
	require.NoError(t, err)
	assert.Contains(t, out, "Switched to context \"ctx2\".")

	ResetForNextCommand(t)

	out, err = ExecuteCommand(t, root, "config", "current-context")
	require.NoError(t, err)
	assert.Equal(t, "ctx2\n", out)
}

func TestCLIConfig_UseContext_NotFound(t *testing.T) {
	root := SetupConfigTest(t)

	_, err := ExecuteCommand(t, root, "config", "use-context", "nonexistent")
	require.Error(t, err, "use-context with nonexistent context should fail")
	assert.Contains(t, err.Error(), "not found")
}

func TestCLIConfig_GetContexts(t *testing.T) {
	root := SetupConfigTest(t)

	WriteConfigFile(t, configFileData{
		CurrentContext: "ctx1",
		Contexts: map[string]contextFileCtx{
			"ctx1": {Name: "ctx1", ServerEndpoint: "http://localhost:8080"},
			"ctx2": {Name: "ctx2", ServerEndpoint: "http://localhost:9090"},
		},
	})

	out, err := ExecuteCommand(t, root, "config", "get-contexts")
	require.NoError(t, err)

	assert.Contains(t, out, "ctx1", "output should list ctx1")
	assert.Contains(t, out, "ctx2", "output should list ctx2")
	assert.Contains(t, out, "Current context:", "output should show current context marker")
}

func TestCLIConfig_CurrentContext(t *testing.T) {
	root := SetupConfigTest(t)

	_, err := ExecuteCommand(t, root, "config", "set-context", "myctx", "--server", "http://localhost:8080")
	require.NoError(t, err)

	ResetForNextCommand(t)

	out, err := ExecuteCommand(t, root, "config", "current-context")
	require.NoError(t, err)
	assert.Equal(t, "myctx\n", out)
}

func TestCLIConfig_NoContexts(t *testing.T) {
	root := SetupConfigTest(t)

	out, err := ExecuteCommand(t, root, "config", "get-contexts")
	require.NoError(t, err)
	assert.Contains(t, out, "No contexts defined.")
}

func TestCLIConfig_CurrentContext_Empty(t *testing.T) {
	root := SetupConfigTest(t)

	out, err := ExecuteCommand(t, root, "config", "current-context")
	require.NoError(t, err)
	assert.Contains(t, out, "No current context is set.")
}
