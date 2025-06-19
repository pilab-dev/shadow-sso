package cmd

import (
	"fmt"
	"os"

	"github.com/pilab-dev/shadow-sso/cmd/ssoctl/config" // Path to your config package
	"github.com/pilab-dev/shadow-sso/log"               // New logger package
	"github.com/rs/zerolog"                             // For zerolog.DebugLevel etc.
	"github.com/spf13/cobra"
	// Viper will be implicitly used via the config package
)

var appLogger log.Logger // Package-level logger

var rootCmd = &cobra.Command{
	Use:   config.AppName,
	Short: "ssoctl is a CLI tool to interact with the Shadow SSO API",
	Long:  `A command-line interface for managing users, service accounts, sessions, and other aspects of the Shadow SSO system.`,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		// Initialize logger early
		// In a real app, level and pretty might come from config or flags
		appLogger = log.NewZerologAdapter(zerolog.DebugLevel, true)
		// Pass context to logger methods
		appLogger.Info(cmd.Context(), "ssoctl CLI starting up", map[string]interface{}{"version": "0.0.1"})

		err := config.InitConfig()
		if err != nil {
			appLogger.Error(cmd.Context(), "Failed to initialize configuration", err)
		}
		return err
	},
}

// Execute adds all child commands to the root command and sets flags appropriately.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		// If appLogger is not initialized due to an error in PersistentPreRunE before logger init,
		// this will panic. A more robust setup might have a default fallback logger.
		// However, PersistentPreRunE for rootCmd usually runs before subcommands.
		// Assuming cmd.Context() is available here, though it might be nil if Execute() itself fails very early.
		// For robustness, a background context could be used if cmd.Context() is unreliable here.
		ctx := context.Background() // Fallback context
		if cmd != nil && cmd.Context() != nil {
			ctx = cmd.Context()
		}
		if appLogger != nil {
			appLogger.Error(ctx, "CLI execution failed", err)
		} else {
			fmt.Fprintln(os.Stderr, "Logger not initialized, CLI execution failed:", err)
		}
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
