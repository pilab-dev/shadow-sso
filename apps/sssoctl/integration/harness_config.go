package integration

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/pilab-dev/shadow-sso/apps/sssoctl/cmd"
	"github.com/pilab-dev/shadow-sso/apps/sssoctl/cmd/config"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"gopkg.in/yaml.v3"
)

// SetupConfigTest creates a standalone test harness for ssoctl config commands.
// It resets all global state (config.GlobalConfig, config.CfgFile, viper)
// and redirects $HOME to a temporary directory so tests never touch
// the real ~/.ssoctl/config.yaml.
//
// Returns the root cobra command ready for SetArgs + Execute.
func SetupConfigTest(t *testing.T) *cobra.Command {
	t.Helper()

	config.GlobalConfig = nil
	config.CfgFile = ""
	viper.Reset()

	home := t.TempDir()
	t.Setenv("HOME", home)

	// Silence usage output on config subcommands so error tests
	// don't have usage text mixed into stdout.
	for _, c := range cmd.RootCmd.Commands() {
		for _, sub := range c.Commands() {
			sub.SilenceUsage = true
		}
	}

	return cmd.RootCmd
}

// ResetForNextCommand resets global config state and viper so the next
// ExecuteCommand re-initializes from the on-disk config file. Use this
// between commands within the same test when earlier commands wrote to
// the config file (e.g. set-context followed by use-context).
func ResetForNextCommand(t *testing.T) {
	t.Helper()
	config.GlobalConfig = nil
	config.CfgFile = ""
	viper.Reset()
}

// ExecuteCommand runs a cobra command with the given args and captures
// stdout output (fmt.Print* and cobra.OutOrStdout).
//
// Stderr output (config init/save messages, cobra error/usage) is
// redirected to /dev/null so it does not pollute test output.
//
// Returns the captured stdout output and any error from cmd.Execute.
func ExecuteCommand(t *testing.T, root *cobra.Command, args ...string) (string, error) {
	t.Helper()

	// Capture stdout
	origStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("failed to create pipe: %v", err)
	}
	os.Stdout = w

	// Redirect cobra's output writer to the pipe
	root.SetOut(w)

	// Discard stderr (config init/save messages + cobra errors go here)
	devNull, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		_ = w.Close()
		t.Fatalf("failed to open /dev/null: %v", err)
	}
	origStderr := os.Stderr
	os.Stderr = devNull
	root.SetErr(devNull)

	root.SetArgs(args)
	execErr := root.Execute()

	// Restore
	_ = w.Close()
	os.Stdout = origStdout
	os.Stderr = origStderr
	_ = devNull.Close()

	var buf bytes.Buffer
	if _, copyErr := io.Copy(&buf, r); copyErr != nil {
		t.Fatalf("failed to read captured output: %v", copyErr)
	}

	return buf.String(), execErr
}

type configFileData struct {
	CurrentContext string                    `yaml:"current_context"`
	Contexts       map[string]contextFileCtx `yaml:"contexts"`
}

type contextFileCtx struct {
	Name           string `yaml:"name"`
	ServerEndpoint string `yaml:"server_endpoint"`
}

// ConfigFilePath returns the path to the config file for the current test HOME.
func ConfigFilePath(t *testing.T) string {
	t.Helper()
	return filepath.Join(os.Getenv("HOME"), ".ssoctl", "config.yaml")
}

// WriteConfigFile writes a CLI config YAML directly to disk (bypassing viper).
// Use this to set up initial config state for tests that need pre-existing
// contexts without going through set-context.
func WriteConfigFile(t *testing.T, data configFileData) {
	t.Helper()
	dir := filepath.Dir(ConfigFilePath(t))
	requireNoErr(t, os.MkdirAll(dir, 0755), "create config dir")
	raw, err := yaml.Marshal(data)
	requireNoErr(t, err, "marshal config")
	requireNoErr(t, os.WriteFile(ConfigFilePath(t), raw, 0644), "write config")
}

func requireNoErr(t *testing.T, err error, msg string) {
	t.Helper()
	if err != nil {
		t.Fatalf("%s: %v", msg, err)
	}
}
