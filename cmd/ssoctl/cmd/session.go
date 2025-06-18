package cmd

import (
	"context"
	"errors"
	"fmt"
	"os"

	// "os" // Not directly used, fmt.Fprintf(os.Stderr,...) is okay

	"connectrpc.com/connect"
	"github.com/pilab-dev/shadow-sso/cmd/ssoctl/client" // Path to your client package
	"github.com/pilab-dev/shadow-sso/cmd/ssoctl/config"
	ssov1 "github.com/pilab-dev/shadow-sso/gen/proto/sso/v1"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3" // For pretty printing session list
)

var sessionCmd = &cobra.Command{
	Use:     "session",
	Short:   "Manage user sessions",
	Aliases: []string{"sessions"},
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		// Ensure config is loaded and current context is available
		if err := config.InitConfig(); err != nil {
			return err
		}
		_, err := config.GetCurrentContext()
		if err != nil {
			return fmt.Errorf("failed to get current context: %w. Use 'ssoctl config set-context' or 'ssoctl auth login'", err)
		}
		return nil
	},
}

var sessionListCmd = &cobra.Command{
	Use:   "list",
	Short: "List active sessions for a user (defaults to current user, admins can specify other user IDs)",
	Long: `Lists active sessions. By default, lists sessions for the currently authenticated user.
If an administrator is authenticated, they can provide a User ID to list sessions for that specific user.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		userID, _ := cmd.Flags().GetString("user-id")

		currentCtx, err := config.GetCurrentContext()
		if err != nil {
			return err
		}

		if userID == "" {
			fmt.Println("Listing sessions for the current authenticated user...")
		} else {
			fmt.Printf("Listing sessions for user ID: %s (requires admin privileges if not self)\n", userID)
		}

		authClient, err := client.AuthServiceClient(currentCtx) // Uses token from currentCtx
		if err != nil {
			return fmt.Errorf("failed to create auth service client: %w", err)
		}

		req := &ssov1.ListUserSessionsRequest{
			UserId: userID, // If empty, server should interpret as current user
		}
		resp, err := authClient.ListUserSessions(context.Background(), connect.NewRequest(req))
		if err != nil {
			return fmt.Errorf("failed to list sessions: %w", err)
		}

		if resp.Msg == nil || len(resp.Msg.Sessions) == 0 {
			fmt.Println("No active sessions found.")
			return nil
		}

		fmt.Println("Active sessions:")
		out, _ := yaml.Marshal(resp.Msg.Sessions)
		fmt.Println(string(out))
		return nil
	},
}

var sessionClearCmd = &cobra.Command{
	Use:   "clear",
	Short: "Clear (revoke) sessions for a user (defaults to current user, admins can specify other user IDs)",
	Long: `Clears/revokes sessions.
Defaults to clearing all sessions for the currently authenticated user if no flags are specified.
If an administrator is authenticated, they can provide a User ID (--user-id) to clear sessions for that user.
Use --session-id to clear a specific session by its ID.
Use --all to clear all sessions for the targeted user (current user by default, or one specified by --user-id).
If clearing all sessions for the current user, this will effectively log out the current CLI session.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		userID, _ := cmd.Flags().GetString("user-id")
		sessionID, _ := cmd.Flags().GetString("session-id") // Specific session to clear
		clearAll, _ := cmd.Flags().GetBool("all")           // Clear all for the target user

		currentCtx, err := config.GetCurrentContext()
		if err != nil {
			return err
		}

		targetUserDescription := "current authenticated user"
		if userID != "" {
			targetUserDescription = fmt.Sprintf("user ID: %s (requires admin privileges if not self)", userID)
		}

		var sessionIDsToClear []string
		if sessionID != "" {
			if clearAll {
				return errors.New("--session-id and --all are mutually exclusive")
			}
			sessionIDsToClear = append(sessionIDsToClear, sessionID)
			fmt.Printf("Clearing session ID: %s for %s...\n", sessionID, targetUserDescription)
		} else if clearAll {
			fmt.Printf("Clearing ALL sessions for %s...\n", targetUserDescription)
			// req.SessionIds will be empty, server interprets as "all"
		} else {
			// Default behavior: clear all sessions for the target user if no specific flags given
			fmt.Printf("Clearing ALL sessions for %s (default behavior, use --session-id for specific)...\n", targetUserDescription)
		}

		authClient, err := client.AuthServiceClient(currentCtx)
		if err != nil {
			return fmt.Errorf("failed to create auth service client: %w", err)
		}

		req := &ssov1.ClearUserSessionsRequest{
			UserId:     userID, // If empty, server should use current authenticated user
			SessionIds: sessionIDsToClear,
		}

		_, err = authClient.ClearUserSessions(context.Background(), connect.NewRequest(req))
		if err != nil {
			return fmt.Errorf("failed to clear sessions: %w", err)
		}

		fmt.Println("Session(s) cleared successfully.")
		// If all sessions for the current user were targeted for clearing
		if userID == "" && (clearAll || sessionID == "") && currentCtx.UserAuthToken != "" {
			isCurrentSessionCleared := true
			if sessionID != "" { // If a specific session was cleared, check if it was the current one
				// This is hard to determine without knowing the current session's ID from the token.
				// For simplicity, assume if a specific session ID was targeted, it might NOT be the current ssoctl session.
				// However, if --all or no specific ID was given for self, then the current session is definitely gone.
				isCurrentSessionCleared = false // Be conservative: only clear local token if explicitly clearing all for self.
				if clearAll {
					isCurrentSessionCleared = true
				} // if --all was specified for self.
				if !clearAll && sessionID == "" {
					isCurrentSessionCleared = true
				} // if no flags specified for self (default to all)
			}

			if isCurrentSessionCleared {
				fmt.Println("Current user's session(s) including potentially the active ssoctl session were cleared. Updating local token state.")
				currentCtx.UserAuthToken = ""
				// Ensure the map in GlobalConfig is updated if currentCtx was a copy
				config.GlobalConfig.Contexts[config.GlobalConfig.CurrentContext] = currentCtx
				if err := config.SaveConfig(); err != nil {
					fmt.Fprintf(os.Stderr, "Warning: failed to clear local token from config: %v\n", err)
				}
			}
		}
		return nil
	},
}

func init() {
	rootCmd.AddCommand(sessionCmd)
	sessionCmd.AddCommand(sessionListCmd)
	sessionCmd.AddCommand(sessionClearCmd)

	sessionListCmd.Flags().String("user-id", "", "ID of the user whose sessions to list (admin only; defaults to current user)")

	sessionClearCmd.Flags().String("user-id", "", "ID of the user whose sessions to clear (admin only; defaults to current user)")
	sessionClearCmd.Flags().String("session-id", "", "Specific session ID to clear")
	sessionClearCmd.Flags().Bool("all", false, "Clear all sessions for the user (if --session-id is not given). For current user, this implies the session used by ssoctl might be cleared.")
}
