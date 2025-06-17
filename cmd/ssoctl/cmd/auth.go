package cmd

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"syscall" // For reading password securely

	"connectrpc.com/connect"
	"github.com/pilab-dev/shadow-sso/cmd/ssoctl/client" // Path to your client package
	"github.com/pilab-dev/shadow-sso/cmd/ssoctl/config"
	ssov1 "github.com/pilab-dev/shadow-sso/gen/sso/v1"
	"github.com/spf13/cobra"
	"golang.org/x/term" // For reading password
)

var authCmd = &cobra.Command{
	Use:   "auth",
	Short: "Manage authentication for ssoctl",
}

var loginCmd = &cobra.Command{
	Use:   "login",
	Short: "Log in to the SSO server and save the session token",
	RunE: func(cmd *cobra.Command, args []string) error {
		currentCtx, err := config.GetCurrentContext()
		if err != nil {
			// This error means no context could be determined (neither current nor defaultable).
			// TODO: Allow --endpoint flag to specify server for login without a pre-existing context.
			return fmt.Errorf("no active context found or could be defaulted. Please set one using 'ssoctl config set-context <name> --server <endpoint>' or 'ssoctl config use-context <name>'. Error: %w", err)
		}

		// If currentCtx.UserAuthToken is already set, perhaps ask to re-login or logout first.
		if currentCtx.UserAuthToken != "" {
			fmt.Printf("Already logged in to context '%s'.\n", config.GlobalConfig.CurrentContext)
			fmt.Print("Do you want to re-login? (yes/no): ")
			reader := bufio.NewReader(os.Stdin)
			confirm, _ := reader.ReadString('\n')
			if strings.TrimSpace(strings.ToLower(confirm)) != "yes" {
				fmt.Println("Login cancelled.")
				return nil
			}
		}

		fmt.Print("Enter email: ")
		reader := bufio.NewReader(os.Stdin)
		email, _ := reader.ReadString('\n')
		email = strings.TrimSpace(email)

		fmt.Print("Enter password: ")
		bytePassword, err := term.ReadPassword(int(syscall.Stdin))
		fmt.Println() // Newline after password input
		if err != nil {
			return fmt.Errorf("failed to read password: %w", err)
		}
		password := string(bytePassword)

		// Create AuthService client without a token for login
		// A temporary config context is made for this call, only containing the server endpoint.
		loginCtxConfig := &config.Context{ServerEndpoint: currentCtx.ServerEndpoint}
		authClient, err := client.AuthServiceClient(loginCtxConfig)
		if err != nil {
			return fmt.Errorf("failed to create auth service client: %w", err)
		}

		loginReq := &ssov1.LoginRequest{
			Email:    email,
			Password: password,
		}
		resp, err := authClient.Login(context.Background(), connect.NewRequest(loginReq))
		if err != nil {
			return fmt.Errorf("login failed: %w", err)
		}

		if resp.Msg == nil || resp.Msg.AccessToken == "" {
			return errors.New("login response did not contain an access token")
		}

		// Save the token to the current context
		currentCtx.UserAuthToken = resp.Msg.AccessToken
		// Ensure the map in GlobalConfig is updated if currentCtx was a copy
		config.GlobalConfig.Contexts[config.GlobalConfig.CurrentContext] = currentCtx
		if err := config.SaveConfig(); err != nil {
			return fmt.Errorf("failed to save token to config: %w", err)
		}

		fmt.Printf("Login successful. Token saved for context '%s'.\n", config.GlobalConfig.CurrentContext)
		if resp.Msg.UserInfo != nil {
			fmt.Printf("Logged in as: %s (ID: %s)\n", resp.Msg.UserInfo.Email, resp.Msg.UserInfo.Id)
		}
		return nil
	},
}

var logoutCmd = &cobra.Command{
	Use:   "logout",
	Short: "Log out from the SSO server by invalidating the current session token",
	RunE: func(cmd *cobra.Command, args []string) error {
		currentCtx, err := config.GetCurrentContext()
		if err != nil {
			return fmt.Errorf("could not determine current context: %w. Not logged in or context not set", err)
		}
		if currentCtx.UserAuthToken == "" {
			fmt.Println("Not logged in (no token found for current context).")
			return nil
		}

		authClient, err := client.AuthServiceClient(currentCtx) // Uses token from currentCtx
		if err != nil {
			return fmt.Errorf("failed to create auth service client: %w", err)
		}

		_, err = authClient.Logout(context.Background(), connect.NewRequest(&ssov1.LogoutRequest{}))
		if err != nil {
			// Still clear local token even if server logout fails, but inform user.
			fmt.Fprintf(os.Stderr, "Server logout failed: %v. Clearing local token anyway.\n", err)
		}

		currentCtx.UserAuthToken = ""
		config.GlobalConfig.Contexts[config.GlobalConfig.CurrentContext] = currentCtx
		if err := config.SaveConfig(); err != nil {
			return fmt.Errorf("failed to clear token from config: %w", err)
		}

		fmt.Printf("Logged out successfully from context '%s'. Local token cleared.\n", config.GlobalConfig.CurrentContext)
		return nil
	},
}

func init() {
	rootCmd.AddCommand(authCmd)
	authCmd.AddCommand(loginCmd)
	authCmd.AddCommand(logoutCmd)
	// loginCmd can have flags for --endpoint, --username, etc. to override context or for non-interactive login
}
