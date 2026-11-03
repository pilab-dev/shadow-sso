package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"text/tabwriter"
	"time"

	"connectrpc.com/connect"
	"github.com/pilab-dev/shadow-sso/apps/sssoctl/cmd/client"
	"github.com/pilab-dev/shadow-sso/apps/sssoctl/cmd/config"
	ssov1 "github.com/pilab-dev/shadow-sso/gen/proto/sso/v1"
	"github.com/pilab-dev/shadow-sso/gen/proto/sso/v1/ssov1connect"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

var sessionCmd = &cobra.Command{
	Use:     "session",
	Short:   "Manage user sessions (list devices, kick sessions)",
	Aliases: []string{"sessions"},
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
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
	Short: "List active sessions (devices) for a user",
	Long: `Lists active sessions. Defaults to the authenticated user; admins can pass --user-id
to inspect another user. The current session is marked with '*'.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		userID, _ := cmd.Flags().GetString("user-id")
		output, _ := cmd.Flags().GetString("output")

		sessions, err := fetchSessions(userID)
		if err != nil {
			return err
		}
		return printSessions(sessions, output)
	},
}

var sessionCurrentCmd = &cobra.Command{
	Use:   "current",
	Short: "Show the session used by this CLI invocation",
	RunE: func(cmd *cobra.Command, args []string) error {
		output, _ := cmd.Flags().GetString("output")
		sessions, err := fetchSessions("")
		if err != nil {
			return err
		}
		var current []*ssov1.SessionInfo
		for _, s := range sessions {
			if s.IsCurrentSession {
				current = append(current, s)
			}
		}
		if len(current) == 0 {
			return errors.New("no current session found; the token may belong to a session that was already revoked")
		}
		return printSessions(current, output)
	},
}

var sessionKickCmd = &cobra.Command{
	Use:     "kick [SESSION_ID]",
	Aliases: []string{"revoke"},
	Short:   "Kick one device by session ID",
	Args:    cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		sessionID := args[0]
		userID, _ := cmd.Flags().GetString("user-id")
		force, _ := cmd.Flags().GetBool("force")

		if err := requireConfirmation(force,
			fmt.Sprintf("Revoke session %s? The device will be signed out.", sessionID)); err != nil {
			return err
		}

		currentID, _ := currentSessionID()
		if _, err := clearSessions(userID, []string{sessionID}); err != nil {
			return err
		}

		fmt.Printf("Session %s revoked.\n", sessionID)
		if currentID != "" && currentID == sessionID {
			fmt.Println("That was the current session; clearing the local token.")
			clearLocalToken()
		}
		return nil
	},
}

var sessionKickAllCmd = &cobra.Command{
	Use:     "kick-all",
	Aliases: []string{"revoke-all"},
	Short:   "Kick every session for a user",
	Long: `Revokes all sessions for the authenticated user, or for --user-id when an admin
is authenticated. This includes the current CLI session.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		userID, _ := cmd.Flags().GetString("user-id")
		force, _ := cmd.Flags().GetBool("force")

		target := userID
		if target == "" {
			target = "the current user"
		}
		if err := requireConfirmation(force,
			fmt.Sprintf("Revoke ALL sessions for %s? Every device will be signed out.", target)); err != nil {
			return err
		}

		if _, err := clearSessions(userID, nil); err != nil {
			return err
		}
		fmt.Println("All sessions revoked.")
		if userID == "" {
			clearLocalToken()
		}
		return nil
	},
}

// sessionLogoutUserCmd logs a user out everywhere. It uses the same gRPC call as
// kick-all but takes an explicit user ID and is meant for admins.
var sessionLogoutUserCmd = &cobra.Command{
	Use:   "logout-user [USER_ID]",
	Short: "Log a user out everywhere (admin)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		userID := args[0]
		force, _ := cmd.Flags().GetBool("force")
		if err := requireConfirmation(force,
			fmt.Sprintf("Revoke ALL sessions for user %s?", userID)); err != nil {
			return err
		}
		if _, err := clearSessions(userID, nil); err != nil {
			return err
		}
		fmt.Printf("All sessions revoked for user %s.\n", userID)
		return nil
	},
}

// sessionClearCmd is kept as a backwards-compatible alias for revoke-all.
var sessionClearCmd = &cobra.Command{
	Use:    "clear",
	Short:  "Deprecated: use 'kick-all' or 'kick <id>'",
	Hidden: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		return sessionKickAllCmd.RunE(cmd, args)
	},
}

func fetchSessions(userID string) ([]*ssov1.SessionInfo, error) {
	authClient, err := authClientFromConfig()
	if err != nil {
		return nil, err
	}
	resp, err := authClient.ListUserSessions(context.Background(), connect.NewRequest(&ssov1.ListUserSessionsRequest{
		UserId: userID,
	}))
	if err != nil {
		return nil, fmt.Errorf("failed to list sessions: %w", err)
	}
	if resp.Msg == nil {
		return nil, nil
	}
	return resp.Msg.Sessions, nil
}

func clearSessions(userID string, sessionIDs []string) (int, error) {
	authClient, err := authClientFromConfig()
	if err != nil {
		return 0, err
	}
	_, err = authClient.ClearUserSessions(context.Background(), connect.NewRequest(&ssov1.ClearUserSessionsRequest{
		UserId:     userID,
		SessionIds: sessionIDs,
	}))
	if err != nil {
		return 0, fmt.Errorf("failed to clear sessions: %w", err)
	}
	return len(sessionIDs), nil
}

func currentSessionID() (string, error) {
	sessions, err := fetchSessions("")
	if err != nil {
		return "", err
	}
	for _, s := range sessions {
		if s.IsCurrentSession {
			return s.Id, nil
		}
	}
	return "", nil
}

func authClientFromConfig() (ssov1connect.AuthServiceClient, error) {
	currentCtx, err := config.GetCurrentContext()
	if err != nil {
		return nil, err
	}
	return client.AuthServiceClient(currentCtx)
}

func printSessions(sessions []*ssov1.SessionInfo, output string) error {
	if len(sessions) == 0 {
		fmt.Println("No active sessions found.")
		return nil
	}

	switch output {
	case "json":
		out, _ := json.MarshalIndent(sessions, "", "  ")
		fmt.Println(string(out))
		return nil
	case "yaml":
		out, _ := yaml.Marshal(sessions)
		fmt.Println(string(out))
		return nil
	case "table", "":
	default:
		return fmt.Errorf("unknown output format %q (table, json, yaml)", output)
	}

	tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "CURRENT\tSESSION ID\tUSER AGENT\tIP ADDRESS\tCREATED\tEXPIRES")
	for _, s := range sessions {
		marker := ""
		if s.IsCurrentSession {
			marker = "*"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n",
			marker, s.Id, shorten(s.UserAgent, 40), s.IpAddress,
			formatTime(s.CreatedAt.AsTime()), formatTime(s.ExpiresAt.AsTime()))
	}
	return tw.Flush()
}

func formatTime(t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	return t.Local().Format("2006-01-02 15:04")
}

func shorten(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-1] + "…"
}

func requireConfirmation(force bool, prompt string) error {
	if force {
		return nil
	}
	fmt.Printf("%s [y/N]: ", prompt)
	var answer string
	_, _ = fmt.Fscanln(os.Stdin, &answer)
	if answer != "y" && answer != "Y" && answer != "yes" {
		return errors.New("aborted")
	}
	return nil
}

// clearLocalToken drops the stored CLI token after the session behind it was
// revoked.
func clearLocalToken() {
	currentCtx, err := config.GetCurrentContext()
	if err != nil || currentCtx.UserAuthToken == "" {
		return
	}
	currentCtx.UserAuthToken = ""
	config.GlobalConfig.Contexts[config.GlobalConfig.CurrentContext] = currentCtx
	if err := config.SaveConfig(); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: failed to clear local token from config: %v\n", err)
	}
}

func init() {
	rootCmd.AddCommand(sessionCmd)
	sessionCmd.AddCommand(sessionListCmd)
	sessionCmd.AddCommand(sessionCurrentCmd)
	sessionCmd.AddCommand(sessionKickCmd)
	sessionCmd.AddCommand(sessionKickAllCmd)
	sessionCmd.AddCommand(sessionLogoutUserCmd)
	sessionCmd.AddCommand(sessionClearCmd)

	sessionListCmd.Flags().String("user-id", "", "ID of the user whose sessions to list (admin only; defaults to current user)")
	sessionListCmd.Flags().StringP("output", "o", "table", "Output format: table, json, yaml")

	sessionCurrentCmd.Flags().StringP("output", "o", "table", "Output format: table, json, yaml")

	sessionKickCmd.Flags().String("user-id", "", "ID of the user owning the session (admin only; defaults to current user)")
	sessionKickCmd.Flags().Bool("force", false, "Do not ask for confirmation")

	sessionKickAllCmd.Flags().String("user-id", "", "ID of the user whose sessions to revoke (admin only; defaults to current user)")
	sessionKickAllCmd.Flags().Bool("force", false, "Do not ask for confirmation")

	sessionLogoutUserCmd.Flags().Bool("force", false, "Do not ask for confirmation")
}
