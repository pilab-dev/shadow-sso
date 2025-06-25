package cmd

import (
	"fmt"
	"os"

	"github.com/pilab-dev/shadow-sso/apps/sssoctl/cmd/config" // Updated path
	"github.com/spf13/cobra"
	// Viper will be implicitly used via the config package
)

var rootCmd = &cobra.Command{
	Use:   config.AppName,
	Short: "ssoctl is a CLI tool to interact with the Shadow SSO API",
	Long:  `A command-line interface for managing users, service accounts, sessions, and other aspects of the Shadow SSO system.`,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		return config.InitConfig()
	},
}

// Execute adds all child commands to the root command and sets flags appropriately.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func init() {
	// CfgFile is already a var in config package, Cobra flag will populate it.
	rootCmd.PersistentFlags().StringVar(&config.CfgFile, "config", "",
		fmt.Sprintf("config file (default is $HOME/.%s/config.yaml)", config.AppName))

	// Add other global flags if needed, e.g., for endpoint or token override.
	// These would typically be checked after config load to override config values.
	// rootCmd.PersistentFlags().String("endpoint", "", "Server endpoint (overrides current context's endpoint)")
	// rootCmd.PersistentFlags().String("token", "", "Auth token (overrides current context's token)")
}
