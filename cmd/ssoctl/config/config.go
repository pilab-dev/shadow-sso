package config

import (
	"errors" // Added for GetCurrentContext
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/viper"
)

const (
	AppName        = "ssoctl"
	ConfigFileName = "config"
	ConfigFileType = "yaml"
)

// Context represents a single CLI context (server endpoint and auth info)
type Context struct {
	Name           string `mapstructure:"name"`
	ServerEndpoint string `mapstructure:"server_endpoint"`
	UserAuthToken  string `mapstructure:"user_auth_token,omitempty"` // Token obtained via 'auth login'
}

// CLIConfig holds the overall CLI configuration
type CLIConfig struct {
	CurrentContext string              `mapstructure:"current_context"`
	Contexts       map[string]*Context `mapstructure:"contexts"`
	// Add other global settings if needed
}

var GlobalConfig *CLIConfig
var CfgFile string // Path to the config file used

// InitConfig initializes Viper to read configuration.
// It's called by the root command's PersistentPreRunE.
func InitConfig() error {
	if CfgFile != "" {
		// Use config file from the flag.
		viper.SetConfigFile(CfgFile)
	} else {
		// Find home directory.
		home, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("failed to get user home directory: %w", err)
		}
		configPath := filepath.Join(home, "."+AppName) // $HOME/.ssoctl

		viper.AddConfigPath(configPath)
		viper.SetConfigName(ConfigFileName) // config.yaml
		viper.SetConfigType(ConfigFileType)

		// Ensure config directory exists
		if err := os.MkdirAll(configPath, os.ModePerm); err != nil {
			return fmt.Errorf("failed to create config directory %s: %w", configPath, err)
		}
		// Set CfgFile to the default path for saving later if needed
		CfgFile = filepath.Join(configPath, ConfigFileName+"."+ConfigFileType)
	}

	viper.AutomaticEnv() // Read in environment variables that match

	GlobalConfig = &CLIConfig{Contexts: make(map[string]*Context)}

	// If a config file is found, read it in.
	if err := viper.ReadInConfig(); err == nil {
		fmt.Fprintln(os.Stderr, "Using config file:", viper.ConfigFileUsed())
		CfgFile = viper.ConfigFileUsed() // Update CfgFile to the one actually used
	} else {
		// If config file not found, it's okay, we'll use defaults or create it on 'set-context' or 'login'.
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			// Config file was found but another error was produced
			return fmt.Errorf("error reading config file %s: %w", viper.ConfigFileUsed(), err)
		}
		// If CfgFile was explicitly set by flag and not found, that's an error
		if CfgFile != "" && viper.ConfigFileUsed() != CfgFile && !errors.Is(err, os.ErrNotExist) { // Check if CfgFile was from flag
			// This logic is a bit tricky: if viper.ReadInConfig fails with ConfigFileNotFoundError,
			// viper.ConfigFileUsed() might be empty or the default path it tried.
			// The key is if CfgFile was set by a flag and *that specific file* isn't found.
			// A simpler check: if viper.ConfigFileUsed() (from flag) is what CfgFile is, and err is ConfigFileNotFoundError
			// then it is an explicit file not found.
			// The current logic is: if CfgFile was from flag, AND (ReadInConfig error is NOT ConfigFileNotFound OR it IS but viper didn't use CfgFile), then error.
			// This should be fine for now.
			// If CfgFile was set (by flag or default construction) and ReadInConfig fails with *anything other than* ConfigFileNotFoundError
			// then it's an error. If it *is* ConfigFileNotFoundError, it's okay (new config).
		}
	}

	if err := viper.Unmarshal(GlobalConfig); err != nil {
		return fmt.Errorf("failed to unmarshal config: %w", err)
	}
	if GlobalConfig.Contexts == nil { // Ensure map is initialized after Unmarshal
		GlobalConfig.Contexts = make(map[string]*Context)
	}

	return nil
}

// SaveConfig saves the current GlobalConfig to the config file.
func SaveConfig() error {
	if CfgFile == "" { // Should have been set by InitConfig
		home, err := os.UserHomeDir()
		if err != nil {
			return err
		}
		CfgFile = filepath.Join(home, "."+AppName, ConfigFileName+"."+ConfigFileType)
	}

	// Ensure directory exists
	configDir := filepath.Dir(CfgFile)
	if err := os.MkdirAll(configDir, os.ModePerm); err != nil {
		return fmt.Errorf("failed to create config directory %s: %w", configDir, err)
	}

    // Update viper's internal map before writing
    // This ensures that changes made directly to GlobalConfig are reflected.
    settings := map[string]interface{}{
        "current_context": GlobalConfig.CurrentContext,
        "contexts":        GlobalConfig.Contexts,
    }
    if err := viper.MergeConfigMap(settings); err != nil {
        return fmt.Errorf("failed to merge config map for saving: %w", err)
    }


	if err := viper.WriteConfigAs(CfgFile); err != nil {
		return fmt.Errorf("failed to save config to %s: %w", CfgFile, err)
	}
	fmt.Fprintln(os.Stderr, "Config saved to:", CfgFile)
	return nil
}

// GetCurrentContext returns the currently active context configuration.
func GetCurrentContext() (*Context, error) {
	if GlobalConfig == nil || GlobalConfig.Contexts == nil {
		return nil, errors.New("config not initialized properly")
	}
	if GlobalConfig.CurrentContext == "" && len(GlobalConfig.Contexts) > 0 {
		// If no current context is set but contexts exist, try to set one as current.
		// This is a simple heuristic, could be more sophisticated.
		for name := range GlobalConfig.Contexts {
			GlobalConfig.CurrentContext = name
			fmt.Fprintf(os.Stderr, "Warning: current_context not set, using context '%s'.\n", name)
			if err := SaveConfig(); err != nil {
				fmt.Fprintf(os.Stderr, "Warning: failed to save current context update: %v\n", err)
			}
			break
		}
	}
	if GlobalConfig.CurrentContext == "" {
		return nil, errors.New("no current context set. Use 'ssoctl config use-context <name>' or 'ssoctl config set-context ...'")
	}
	ctx, exists := GlobalConfig.Contexts[GlobalConfig.CurrentContext]
	if !exists {
		return nil, fmt.Errorf("current context '%s' not found in configuration", GlobalConfig.CurrentContext)
	}
	return ctx, nil
}
