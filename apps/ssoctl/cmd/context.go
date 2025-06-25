package cmd

import (
	"errors" // Added for setContextCmd
	"fmt"

	"github.com/pilab-dev/shadow-sso/apps/ssoctl/cmd/config"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3" // For pretty printing contexts
)

var configCmd = &cobra.Command{
	Use:     "config",
	Short:   "Manage ssoctl configuration and contexts",
	Aliases: []string{"cfg"},
}

var getContextsCmd = &cobra.Command{
	Use:     "get-contexts",
	Short:   "Display one or many contexts",
	Aliases: []string{"get"},
	RunE: func(cmd *cobra.Command, args []string) error {
		if config.GlobalConfig == nil || len(config.GlobalConfig.Contexts) == 0 {
			fmt.Println("No contexts defined.")
			return nil
		}
		// Pretty print using YAML or a table
		out, err := yaml.Marshal(config.GlobalConfig.Contexts)
		if err != nil {
			return fmt.Errorf("failed to marshal contexts to YAML: %w", err)
		}
		fmt.Println(string(out))
		if config.GlobalConfig.CurrentContext != "" {
			fmt.Printf("Current context: %s\n", config.GlobalConfig.CurrentContext)
		} else {
			fmt.Println("No current context set.")
		}
		return nil
	},
}

var useContextCmd = &cobra.Command{
	Use:     "use-context [CONTEXT_NAME]",
	Short:   "Sets the current-context in the config file",
	Aliases: []string{"use"},
	Args:    cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		contextName := args[0]
		if config.GlobalConfig == nil { // Should be initialized by PersistentPreRunE
			return errors.New("config not initialized")
		}
		if _, exists := config.GlobalConfig.Contexts[contextName]; !exists {
			return fmt.Errorf("context '%s' not found", contextName)
		}
		config.GlobalConfig.CurrentContext = contextName
		if err := config.SaveConfig(); err != nil {
			return fmt.Errorf("failed to save config: %w", err)
		}
		fmt.Printf("Switched to context \"%s\".\n", contextName)
		return nil
	},
}

var setContextCmd = &cobra.Command{
	Use:     "set-context [CONTEXT_NAME]",
	Short:   "Sets a context entry in the config",
	Aliases: []string{"set"},
	Args:    cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		contextName := args[0]
		server, _ := cmd.Flags().GetString("server")
		// token, _ := cmd.Flags().GetString("token") // Token set by 'auth login'

		if server == "" {
			return errors.New("--server flag is required")
		}
		if config.GlobalConfig == nil { // Should be initialized
			return errors.New("config not initialized")
		}
		if config.GlobalConfig.Contexts == nil {
			config.GlobalConfig.Contexts = make(map[string]*config.Context)
		}

		ctxEntry, exists := config.GlobalConfig.Contexts[contextName]
		if !exists {
			ctxEntry = &config.Context{Name: contextName}
			config.GlobalConfig.Contexts[contextName] = ctxEntry
		}
		ctxEntry.ServerEndpoint = server
		// ctxEntry.UserAuthToken = token // Only update if token flag is provided and not empty

		// If this is the only context, or no current context is set, make it current.
		if len(config.GlobalConfig.Contexts) == 1 || config.GlobalConfig.CurrentContext == "" {
			config.GlobalConfig.CurrentContext = contextName
		}

		if err := config.SaveConfig(); err != nil {
			return fmt.Errorf("failed to save config: %w", err)
		}
		fmt.Printf("Context \"%s\" created/modified.\n", contextName)
		return nil
	},
}

var currentContextCmd = &cobra.Command{
	Use:   "current-context",
	Short: "Displays the current-context",
	RunE: func(cmd *cobra.Command, args []string) error {
		if config.GlobalConfig == nil || config.GlobalConfig.CurrentContext == "" {
			fmt.Println("No current context is set.")
			return nil
		}
		fmt.Println(config.GlobalConfig.CurrentContext)
		return nil
	},
}

func init() {
	rootCmd.AddCommand(configCmd)
	configCmd.AddCommand(getContextsCmd)
	configCmd.AddCommand(useContextCmd)
	configCmd.AddCommand(setContextCmd)
	configCmd.AddCommand(currentContextCmd)

	setContextCmd.Flags().String("server", "", "The address and port of the SSO server")
	// setContextCmd.Flags().String("token", "", "User authentication token for this context (usually set by 'auth login')")
}
