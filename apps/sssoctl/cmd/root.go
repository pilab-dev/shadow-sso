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

	// --no-interactive disables all prompts and TUI wizards. Commands that need
	// missing parameters then fail with the list of required flags.
	rootCmd.PersistentFlags().BoolVar(&noInteractive, "no-interactive", false,
		"Never prompt or launch a TUI; fail when required parameters are missing")

	// --protocol selects the wire protocol for proto-based commands. The server
	// accepts Connect, gRPC and gRPC-Web on the same port.
	rootCmd.PersistentFlags().StringVar(&config.ProtocolOverride, "protocol", "",
		"RPC protocol for proto commands: connect (default), connect-proto, grpc")
}
