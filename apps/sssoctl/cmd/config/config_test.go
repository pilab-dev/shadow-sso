package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestSaveConfig_OmitsEmptyToken(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "config.yaml")
	CfgFile = cfgPath
	GlobalConfig = &CLIConfig{
		CurrentContext: "test",
		Contexts: map[string]*Context{
			"test": {
				Name:           "test",
				ServerEndpoint: "http://localhost:8080",
				UserAuthToken:  "",
			},
		},
	}

	require.NoError(t, SaveConfig())

	data, err := os.ReadFile(cfgPath)
	require.NoError(t, err)

	var parsed map[string]any
	require.NoError(t, yaml.Unmarshal(data, &parsed))

	contexts, ok := parsed["contexts"].(map[string]any)
	require.True(t, ok)
	testCtx, ok := contexts["test"].(map[string]any)
	require.True(t, ok)
	_, hasToken := testCtx["user_auth_token"]
	assert.False(t, hasToken, "empty token should be omitted from config file")
}

func TestSaveConfig_IncludesNonEmptyToken(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "config.yaml")
	CfgFile = cfgPath
	GlobalConfig = &CLIConfig{
		CurrentContext: "test",
		Contexts: map[string]*Context{
			"test": {
				Name:           "test",
				ServerEndpoint: "http://localhost:8080",
				UserAuthToken:  "my-secret-token",
			},
		},
	}

	require.NoError(t, SaveConfig())

	data, err := os.ReadFile(cfgPath)
	require.NoError(t, err)

	var parsed map[string]any
	require.NoError(t, yaml.Unmarshal(data, &parsed))

	contexts, ok := parsed["contexts"].(map[string]any)
	require.True(t, ok)
	testCtx, ok := contexts["test"].(map[string]any)
	require.True(t, ok)
	token, hasToken := testCtx["user_auth_token"]
	assert.True(t, hasToken, "non-empty token should be present in config file")
	assert.Equal(t, "my-secret-token", token)
}
