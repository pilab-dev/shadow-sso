package cmd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings" // For password confirmation
	"syscall" // For password reading

	"connectrpc.com/connect"
	"github.com/pilab-dev/shadow-sso/cmd/ssoctl/client"
	"github.com/pilab-dev/shadow-sso/cmd/ssoctl/config"
	ssov1 "github.com/pilab-dev/shadow-sso/gen/sso/v1"
	"github.com/spf13/cobra"
	"golang.org/x/term" // For password reading
	"gopkg.in/yaml.v3"   // For pretty printing user/list
)

var userCmd = &cobra.Command{
	Use:     "user",
	Short:   "Manage users",
	Aliases: []string{"users"},
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		// Ensure config is loaded and current context is available for client setup
		// This is usually handled by rootCmd's PersistentPreRunE, but can be re-ensured here.
		if err := config.InitConfig(); err != nil {
			return err
		}
		_, err := config.GetCurrentContext() // Check if context can be determined
		if err != nil {
			// Provide a more specific message if context is absolutely required now.
			// For some commands like 'ssoctl user register' if it were unauthenticated, this might not be an error.
			// But since UserServiceClient requires auth, a context with token is generally needed.
			return fmt.Errorf("failed to get current context: %w. Use 'ssoctl config set-context' or 'ssoctl auth login'", err)
		}
		return nil
	},
}

var userRegisterCmd = &cobra.Command{
	Use:   "register",
	Short: "Register a new user (requires admin privileges)",
	RunE: func(cmd *cobra.Command, args []string) error {
		email, _ := cmd.Flags().GetString("email")
		password, _ := cmd.Flags().GetString("password")
		firstName, _ := cmd.Flags().GetString("first-name")
		lastName, _ := cmd.Flags().GetString("last-name")

		if email == "" {
			return errors.New("email is required via --email flag")
		}
		// Password can be prompted if not provided via flag
		if password == "" {
			fmt.Print("Enter password: ")
			bytePassword, err := term.ReadPassword(int(syscall.Stdin))
			fmt.Println()
			if err != nil {
				return fmt.Errorf("failed to read password: %w", err)
			}
			password = string(bytePassword)
			if len(password) < 8 { // Example policy
				return errors.New("password must be at least 8 characters")
			}
			fmt.Print("Confirm password: ")
			byteConfirmPassword, err := term.ReadPassword(int(syscall.Stdin))
			fmt.Println()
			if err != nil {
				return fmt.Errorf("failed to read password confirmation: %w", err)
			}
			if password != string(byteConfirmPassword) {
				return errors.New("passwords do not match")
			}
		}

		currentCtx, err := config.GetCurrentContext()
		if err != nil {
			return err
		} // UserServiceClient below will check for token

		userClient, err := client.UserServiceClient(currentCtx)
		if err != nil {
			return err
		}

		req := &ssov1.RegisterUserRequest{
			Email: email, Password: password, FirstName: firstName, LastName: lastName,
		}
		resp, err := userClient.RegisterUser(context.Background(), connect.NewRequest(req))
		if err != nil {
			return fmt.Errorf("user registration failed: %w", err)
		}

		fmt.Println("User registered successfully:")
		out, _ := yaml.Marshal(resp.Msg.User) // Assuming resp.Msg.User is the user object
		fmt.Println(string(out))
		return nil
	},
}

var userGetCmd = &cobra.Command{
	Use:   "get [USER_ID_OR_EMAIL]",
	Short: "Get user details by ID or email",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		userIDOrEmail := args[0]
		currentCtx, err := config.GetCurrentContext()
		if err != nil {
			return err
		}
		userClient, err := client.UserServiceClient(currentCtx)
		if err != nil {
			return err
		}

		req := &ssov1.GetUserRequest{UserId: userIDOrEmail} // Server will determine if it's ID or email
		resp, err := userClient.GetUser(context.Background(), connect.NewRequest(req))
		if err != nil {
			return fmt.Errorf("failed to get user: %w", err)
		}

		out, _ := yaml.Marshal(resp.Msg.User)
		fmt.Println(string(out))
		return nil
	},
}

var userListCmd = &cobra.Command{
	Use:   "list",
	Short: "List users with pagination",
	RunE: func(cmd *cobra.Command, args []string) error {
		pageSize, _ := cmd.Flags().GetInt32("page-size")
		pageToken, _ := cmd.Flags().GetString("page-token")

		currentCtx, err := config.GetCurrentContext()
		if err != nil {
			return err
		}
		userClient, err := client.UserServiceClient(currentCtx)
		if err != nil {
			return err
		}

		req := &ssov1.ListUsersRequest{PageSize: pageSize, PageToken: pageToken}
		resp, err := userClient.ListUsers(context.Background(), connect.NewRequest(req))
		if err != nil {
			return fmt.Errorf("failed to list users: %w", err)
		}

		if len(resp.Msg.Users) == 0 {
			fmt.Println("No users found.")
			return nil
		}
		out, _ := yaml.Marshal(resp.Msg.Users)
		fmt.Println(string(out))
		if resp.Msg.NextPageToken != "" {
			fmt.Printf("\nNext page token: %s\n", resp.Msg.NextPageToken)
		}
		return nil
	},
}

var userActivateCmd = &cobra.Command{
	Use:   "activate [USER_ID_OR_EMAIL]",
	Short: "Activate a user account",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		userIDOrEmail := args[0]
		currentCtx, err := config.GetCurrentContext()
		if err != nil {
			return err
		}
		userClient, err := client.UserServiceClient(currentCtx)
		if err != nil {
			return err
		}

		req := &ssov1.ActivateUserRequest{UserId: userIDOrEmail}
		_, err = userClient.ActivateUser(context.Background(), connect.NewRequest(req))
		if err != nil {
			return fmt.Errorf("failed to activate user: %w", err)
		}
		fmt.Printf("User %s activated successfully.\n", userIDOrEmail)
		return nil
	},
}

var userLockCmd = &cobra.Command{
	Use:   "lock [USER_ID_OR_EMAIL]",
	Short: "Lock a user account",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		userIDOrEmail := args[0]
		currentCtx, err := config.GetCurrentContext()
		if err != nil {
			return err
		}
		userClient, err := client.UserServiceClient(currentCtx)
		if err != nil {
			return err
		}

		req := &ssov1.LockUserRequest{UserId: userIDOrEmail}
		_, err = userClient.LockUser(context.Background(), connect.NewRequest(req))
		if err != nil {
			return fmt.Errorf("failed to lock user: %w", err)
		}
		fmt.Printf("User %s locked successfully.\n", userIDOrEmail)
		return nil
	},
}

var userChangePasswordCmd = &cobra.Command{
	Use:   "change-password [USER_ID_OR_EMAIL]",
	Short: "Change a user's password (admin) or current user's password",
	Args:  cobra.ExactArgs(1), // User for whom password change is intended
	RunE: func(cmd *cobra.Command, args []string) error {
		userIDOrEmail := args[0]
		oldPassword, _ := cmd.Flags().GetString("old-password") // For current user changing their own
		newPassword, _ := cmd.Flags().GetString("new-password")

		if newPassword == "" {
			fmt.Print("Enter new password: ")
			bytePassword, err := term.ReadPassword(int(syscall.Stdin))
			fmt.Println()
			if err != nil {
				return fmt.Errorf("failed to read new password: %w", err)
			}
			newPassword = string(bytePassword)
			if len(newPassword) < 8 {
				return errors.New("new password must be at least 8 characters")
			}
			fmt.Print("Confirm new password: ")
			byteConfirmPassword, err := term.ReadPassword(int(syscall.Stdin))
			fmt.Println()
			if err != nil {
				return fmt.Errorf("failed to read password confirmation: %w", err)
			}
			if newPassword != string(byteConfirmPassword) {
				return errors.New("new passwords do not match")
			}
		}
		// oldPassword might be empty if admin is forcing a change. Server should handle this logic.

		currentCtx, err := config.GetCurrentContext()
		if err != nil {
			return err
		}
		userClient, err := client.UserServiceClient(currentCtx)
		if err != nil {
			return err
		}

		req := &ssov1.ChangePasswordRequest{
			UserId: userIDOrEmail, OldPassword: oldPassword, NewPassword: newPassword,
		}
		_, err = userClient.ChangePassword(context.Background(), connect.NewRequest(req))
		if err != nil {
			return fmt.Errorf("failed to change password: %w", err)
		}
		fmt.Printf("Password changed successfully for user %s.\n", userIDOrEmail)
		return nil
	},
}

func init() {
	rootCmd.AddCommand(userCmd)
	userCmd.AddCommand(userRegisterCmd)
	userCmd.AddCommand(userGetCmd)
	userCmd.AddCommand(userListCmd)
	userCmd.AddCommand(userActivateCmd)
	userCmd.AddCommand(userLockCmd)
	userCmd.AddCommand(userChangePasswordCmd)

	userRegisterCmd.Flags().StringP("email", "e", "", "User's email address")
	userRegisterCmd.Flags().StringP("password", "p", "", "User's password (will prompt if not provided)")
	userRegisterCmd.Flags().String("first-name", "", "User's first name")
	userRegisterCmd.Flags().String("last-name", "", "User's last name")

	userListCmd.Flags().Int32("page-size", 10, "Number of users to list per page")
	userListCmd.Flags().String("page-token", "", "Token for the next page of results")

	userChangePasswordCmd.Flags().String("old-password", "", "Current password (if user is changing their own)")
	userChangePasswordCmd.Flags().String("new-password", "", "New password (will prompt if not provided)")

	// Add 2fa command group to userCmd
	userCmd.AddCommand(user2faCmd)
	user2faCmd.AddCommand(user2faSetupCmd)
	user2faCmd.AddCommand(user2faVerifyCmd)
	user2faCmd.AddCommand(user2faDisableCmd)
	user2faCmd.AddCommand(user2faRecoveryCodesCmd)

	user2faDisableCmd.Flags().StringP("password-or-code", "p", "", "Current password, TOTP code, or a recovery code to confirm disabling 2FA")
	user2faRecoveryCodesCmd.Flags().StringP("password-or-code", "p", "", "Current password or a TOTP code for re-authentication (optional, server may require if not recently authenticated)")
}

// --- 2FA Commands ---

var user2faCmd = &cobra.Command{
	Use:   "2fa",
	Short: "Manage Two-Factor Authentication for your account",
}

var user2faSetupCmd = &cobra.Command{
	Use:   "setup",
	Short: "Initiate TOTP setup for your account",
	RunE: func(cmd *cobra.Command, args []string) error {
		currentCtx, err := config.GetCurrentContext()
		if err != nil {
			return err
		}
		apiClient, err := client.TwoFactorServiceClient(currentCtx) // Use TwoFactorServiceClient
		if err != nil {
			return err
		}

		req := &ssov1.InitiateTOTPSetupRequest{}
		resp, err := apiClient.InitiateTOTPSetup(context.Background(), connect.NewRequest(req))
		if err != nil {
			return fmt.Errorf("failed to initiate TOTP setup: %w", err)
		}

		if resp.Msg == nil {
			return errors.New("no response from server")
		}

		fmt.Println("TOTP Setup Initiated:")
		fmt.Printf("  Secret (for manual entry): %s\n", resp.Msg.Secret)
		fmt.Printf("  QR Code URI: %s\n", resp.Msg.QrCodeUri)
		fmt.Println("\nScan the QR code with your authenticator app (e.g., Google Authenticator, Authy).")
		fmt.Println("You can also display the QR code in the terminal if your terminal supports it.")

		// Attempt to display QR code in terminal
		// Using github.com/skip2/go-qrcode to generate PNG then attempting to display
		// This is a placeholder as direct terminal QR display is complex.
		// A library like github.com/mdp/qrterminal would be better for console text.
		_, errQr := qrcode.New(resp.Msg.QrCodeUri, qrcode.Medium)
		if errQr == nil {
			fmt.Println("\nAlternatively, use a QR code generator with the URI above, or a CLI QR tool to display the URI.")
			// Example: qrterminal.GenerateHalfBlock(resp.Msg.QrCodeUri, qrterminal.L, os.Stdout)
			// Would require importing "github.com/mdp/qrterminal"
		} else {
			fmt.Printf("\n(Could not instantiate QR code for further processing: %v)\n", errQr)
			fmt.Println("Please use the URI/secret manually with your authenticator app.")
		}

		fmt.Println("\nAfter scanning/entering, use 'ssoctl user 2fa verify <TOTP_CODE>' to enable 2FA.")
		return nil
	},
}

var user2faVerifyCmd = &cobra.Command{
	Use:   "verify [TOTP_CODE]",
	Short: "Verify a TOTP code to enable 2FA for your account",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		totpCode := args[0]
		currentCtx, err := config.GetCurrentContext()
		if err != nil {
			return err
		}
		apiClient, err := client.TwoFactorServiceClient(currentCtx)
		if err != nil {
			return err
		}

		req := &ssov1.VerifyAndEnableTOTPRequest{TotpCode: totpCode}
		resp, err := apiClient.VerifyAndEnableTOTP(context.Background(), connect.NewRequest(req))
		if err != nil {
			return fmt.Errorf("failed to verify TOTP code and enable 2FA: %w", err)
		}

		if resp.Msg == nil {
			return errors.New("no response from server")
		}
		fmt.Println("2FA (TOTP) enabled successfully!")
		fmt.Println("Store these recovery codes securely. They can be used if you lose access to your 2FA device:")
		for i, code := range resp.Msg.RecoveryCodes {
			fmt.Printf("  %d. %s\n", i+1, code)
		}
		return nil
	},
}

var user2faDisableCmd = &cobra.Command{
	Use:   "disable",
	Short: "Disable 2FA for your account",
	RunE: func(cmd *cobra.Command, args []string) error {
		passwordOrCode, _ := cmd.Flags().GetString("password-or-code")
		if passwordOrCode == "" {
			fmt.Print("Enter current password or a 2FA code (TOTP/Recovery) to confirm disabling 2FA: ")
			byteInput, err := term.ReadPassword(int(syscall.Stdin))
			fmt.Println()
			if err != nil {
				return fmt.Errorf("failed to read confirmation: %w", err)
			}
			passwordOrCode = string(byteInput)
		}
		if passwordOrCode == "" {
			return errors.New("confirmation (password or 2FA code) is required")
		}

		currentCtx, err := config.GetCurrentContext()
		if err != nil {
			return err
		}
		apiClient, err := client.TwoFactorServiceClient(currentCtx)
		if err != nil {
			return err
		}

		req := &ssov1.Disable2FARequest{PasswordOr_2FaCode: passwordOrCode}
		_, err = apiClient.Disable2FA(context.Background(), connect.NewRequest(req))
		if err != nil {
			return fmt.Errorf("failed to disable 2FA: %w", err)
		}

		fmt.Println("2FA disabled successfully for your account.")
		return nil
	},
}

var user2faRecoveryCodesCmd = &cobra.Command{
	Use:   "recovery-codes",
	Short: "Generate a new set of recovery codes (invalidates old ones)",
	RunE: func(cmd *cobra.Command, args []string) error {
		passwordOrCode, _ := cmd.Flags().GetString("password-or-code") // Optional for re-auth

		currentCtx, err := config.GetCurrentContext()
		if err != nil {
			return err
		}
		apiClient, err := client.TwoFactorServiceClient(currentCtx)
		if err != nil {
			return err
		}

		req := &ssov1.GenerateRecoveryCodesRequest{PasswordOr_2FaCode: passwordOrCode}
		resp, err := apiClient.GenerateRecoveryCodes(context.Background(), connect.NewRequest(req))
		if err != nil {
			return fmt.Errorf("failed to generate new recovery codes: %w", err)
		}

		if resp.Msg == nil {
			return errors.New("no response from server")
		}
		fmt.Println("New recovery codes generated. Store these securely (they replace any old codes):")
		for i, code := range resp.Msg.RecoveryCodes {
			fmt.Printf("  %d. %s\n", i+1, code)
		}
		return nil
	},
}
