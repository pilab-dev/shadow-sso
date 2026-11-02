package cmd

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"connectrpc.com/connect"
	"github.com/mdp/qrterminal"
	"github.com/pilab-dev/shadow-sso/apps/sssoctl/cmd/client"
	"github.com/pilab-dev/shadow-sso/apps/sssoctl/cmd/config"
	ssov1 "github.com/pilab-dev/shadow-sso/gen/proto/sso/v1"
	"github.com/spf13/cobra"
)

var mfaCmd = &cobra.Command{
	Use:     "mfa",
	Short:   "Manage multi-factor authentication for users (admin)",
	Aliases: []string{"2fa"},
}

// --- status ---

var mfaStatusCmd = &cobra.Command{
	Use:   "status [USER_ID_OR_EMAIL]",
	Short: "Explain every second factor configured for a user",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		currentCtx, err := config.GetCurrentContext()
		if err != nil {
			return err
		}
		c, err := client.TwoFactorServiceClient(currentCtx)
		if err != nil {
			return err
		}
		resp, err := c.GetMFAStatus(context.Background(), connect.NewRequest(&ssov1.GetMFAStatusRequest{UserId: args[0]}))
		if err != nil {
			return fmt.Errorf("failed to get MFA status: %w", err)
		}
		s := resp.Msg.GetStatus()
		if s == nil {
			fmt.Println("No MFA status returned.")
			return nil
		}
		fmt.Printf("User:                    %s\n", args[0])
		fmt.Printf("MFA configured:          %t\n", s.GetEnabled())
		fmt.Printf("Effective trigger:       %s\n", s.GetEffectiveTrigger())
		fmt.Printf("TOTP usable by web:      %t\n", s.GetTotpEnabled())
		fmt.Printf("TOTP secret present:     %t\n", s.GetTotpSecretSet())
		fmt.Printf("Email MFA enabled:       %t\n", s.GetEmailMfaEnabled())
		fmt.Printf("Push MFA enabled:        %t\n", s.GetPushMfaEnabled())
		fmt.Printf("Verified MFA methods:    %d\n", s.GetVerifiedMethods())
		fmt.Printf("WebAuthn devices:        %d\n", s.GetWebauthnDevices())
		fmt.Printf("Recovery codes remaining:%d\n", s.GetRecoveryCodesRemaining())
		fmt.Printf("MFA required (user):     %t\n", s.GetMfaRequired())
		fmt.Printf("MFA required (realm):    %t\n", s.GetRealmRequiresMfa())
		fmt.Printf("MFA required (flow):     %t\n", s.GetFlowRequiresMfa())
		if notes := s.GetNotes(); len(notes) > 0 {
			fmt.Println("\nWarnings:")
			for _, note := range notes {
				fmt.Printf("  - %s\n", note)
			}
		}
		return nil
	},
}

// --- reset ---

var mfaResetCmd = &cobra.Command{
	Use:   "reset [USER_ID_OR_EMAIL]",
	Short: "Clear every second factor for a user (flags, TOTP, recovery codes, methods)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		removePasskeys, _ := cmd.Flags().GetBool("remove-passkeys")
		yes, _ := cmd.Flags().GetBool("yes")

		currentCtx, err := config.GetCurrentContext()
		if err != nil {
			return err
		}
		c, err := client.TwoFactorServiceClient(currentCtx)
		if err != nil {
			return err
		}

		if !yes {
			status, err := c.GetMFAStatus(context.Background(), connect.NewRequest(&ssov1.GetMFAStatusRequest{UserId: args[0]}))
			if err == nil && status.Msg.GetStatus() != nil {
				fmt.Printf("Current MFA state for %s: trigger=%s, totp_usable=%t, recovery_codes=%d, passkeys=%d\n",
					args[0],
					status.Msg.GetStatus().GetEffectiveTrigger(),
					status.Msg.GetStatus().GetTotpEnabled(),
					status.Msg.GetStatus().GetRecoveryCodesRemaining(),
					status.Msg.GetStatus().GetWebauthnDevices())
			}
			fmt.Printf("This clears all second factors for %s. Type 'yes' to continue: ", args[0])
			reader := bufio.NewReader(os.Stdin)
			answer, _ := reader.ReadString('\n')
			if strings.TrimSpace(strings.ToLower(answer)) != "yes" {
				fmt.Println("Aborted.")
				return nil
			}
		}

		resp, err := c.ResetUserMFA(context.Background(), connect.NewRequest(&ssov1.ResetUserMFARequest{
			UserId:         args[0],
			RemovePasskeys: removePasskeys,
		}))
		if err != nil {
			return fmt.Errorf("failed to reset MFA: %w", err)
		}
		prev := resp.Msg.GetPrevious()
		fmt.Printf("MFA reset for %s (previous trigger: %s, passkeys removed: %t).\n",
			args[0], prev.GetEffectiveTrigger(), resp.Msg.GetRemovedPasskeys())
		if prev.GetMfaRequired() {
			fmt.Println("Note: the user still has the 'MFA required' flag set; the next login will force enrollment.")
		}
		return nil
	},
}

// --- require ---

var mfaRequireCmd = &cobra.Command{
	Use:   "require [USER_ID_OR_EMAIL]",
	Short: "Force (or stop forcing) a second factor for a user",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		off, _ := cmd.Flags().GetBool("off")
		required := !off

		currentCtx, err := config.GetCurrentContext()
		if err != nil {
			return err
		}
		c, err := client.TwoFactorServiceClient(currentCtx)
		if err != nil {
			return err
		}
		_, err = c.SetUserMFARequired(context.Background(), connect.NewRequest(&ssov1.SetUserMFARequiredRequest{
			UserId:   args[0],
			Required: required,
		}))
		if err != nil {
			return fmt.Errorf("failed to update MFA requirement: %w", err)
		}
		fmt.Printf("MFA required set to %t for %s.\n", required, args[0])
		if required {
			fmt.Println("Users without a TOTP factor will be sent to enrollment on their next login.")
		}
		return nil
	},
}

// --- TOTP enrollment ---

var mfaTotpCmd = &cobra.Command{
	Use:   "totp",
	Short: "Manage TOTP factors",
}

var mfaTotpEnrollCmd = &cobra.Command{
	Use:   "enroll [USER_ID_OR_EMAIL]",
	Short: "Start TOTP enrollment and confirm it with a code",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		code, _ := cmd.Flags().GetString("code")
		currentCtx, err := config.GetCurrentContext()
		if err != nil {
			return err
		}
		c, err := client.TwoFactorServiceClient(currentCtx)
		if err != nil {
			return err
		}

		setup, err := c.InitiateTOTPSetup(context.Background(), connect.NewRequest(&ssov1.InitiateTOTPSetupRequest{UserId: args[0]}))
		if err != nil {
			return fmt.Errorf("failed to start TOTP setup: %w (if 2FA is already enabled, run 'ssoctl mfa reset %s' first)", err, args[0])
		}
		fmt.Printf("TOTP secret for %s: %s\n", args[0], setup.Msg.GetSecret())
		qrterminal.GenerateHalfBlock(setup.Msg.GetQrCodeUri(), qrterminal.L, os.Stdout)

		if code == "" {
			fmt.Print("Enter the 6-digit code from the authenticator: ")
			reader := bufio.NewReader(os.Stdin)
			code, _ = reader.ReadString('\n')
			code = strings.TrimSpace(code)
		}
		if code == "" {
			return errors.New("a TOTP code is required to finish enrollment")
		}

		verify, err := c.VerifyAndEnableTOTP(context.Background(), connect.NewRequest(&ssov1.VerifyAndEnableTOTPRequest{
			UserId:   args[0],
			TotpCode: code,
		}))
		if err != nil {
			return fmt.Errorf("failed to verify TOTP code: %w", err)
		}
		fmt.Println("TOTP enabled.")
		if codes := verify.Msg.GetRecoveryCodes(); len(codes) > 0 {
			fmt.Println("Recovery codes (store securely, shown once):")
			for i, rc := range codes {
				fmt.Printf("  %d. %s\n", i+1, rc)
			}
		}
		return nil
	},
}

// --- recovery codes ---

var mfaRecoveryCmd = &cobra.Command{
	Use:   "recovery",
	Short: "Manage recovery codes",
}

var mfaRecoveryGenerateCmd = &cobra.Command{
	Use:   "generate [USER_ID_OR_EMAIL]",
	Short: "Generate a new set of recovery codes (invalidates old ones)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		currentCtx, err := config.GetCurrentContext()
		if err != nil {
			return err
		}
		c, err := client.TwoFactorServiceClient(currentCtx)
		if err != nil {
			return err
		}
		resp, err := c.GenerateRecoveryCodes(context.Background(), connect.NewRequest(&ssov1.GenerateRecoveryCodesRequest{UserId: args[0]}))
		if err != nil {
			return fmt.Errorf("failed to generate recovery codes: %w", err)
		}
		fmt.Println("New recovery codes (store securely, shown once):")
		for i, code := range resp.Msg.GetRecoveryCodes() {
			fmt.Printf("  %d. %s\n", i+1, code)
		}
		return nil
	},
}

// --- list ---

var mfaListCmd = &cobra.Command{
	Use:   "list [USER_ID_OR_EMAIL]",
	Short: "List registered MFA methods and passkeys",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		currentCtx, err := config.GetCurrentContext()
		if err != nil {
			return err
		}
		uc, err := client.UserServiceClient(currentCtx)
		if err != nil {
			return err
		}
		methods, err := uc.ListMfaMethods(context.Background(), connect.NewRequest(&ssov1.ListMfaMethodsRequest{UserId: args[0]}))
		if err != nil {
			return fmt.Errorf("failed to list MFA methods: %w", err)
		}
		fmt.Println("MFA methods:")
		if len(methods.Msg.GetMethods()) == 0 {
			fmt.Println("  (none)")
		}
		for _, m := range methods.Msg.GetMethods() {
			fmt.Printf("  %s  type=%s verified=%t name=%q\n", m.GetId(), m.GetType(), m.GetVerified(), m.GetName())
		}

		devices, err := uc.ListWebAuthnDevices(context.Background(), connect.NewRequest(&ssov1.ListWebAuthnDevicesRequest{UserId: args[0]}))
		if err != nil {
			return fmt.Errorf("failed to list passkeys: %w", err)
		}
		fmt.Println("\nPasskeys / WebAuthn devices:")
		if len(devices.Msg.GetDevices()) == 0 {
			fmt.Println("  (none)")
		}
		for _, d := range devices.Msg.GetDevices() {
			fmt.Printf("  %s  name=%q created=%s transports=%v\n", d.GetId(), d.GetName(), d.GetCreatedAt().AsTime().Format("2006-01-02"), d.GetTransports())
		}
		return nil
	},
}

// --- passkeys ---

var mfaPasskeyCmd = &cobra.Command{
	Use:   "passkey",
	Short: "Manage registered WebAuthn devices",
}

var mfaPasskeyListCmd = &cobra.Command{
	Use:   "list [USER_ID_OR_EMAIL]",
	Short: "List registered passkeys",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		currentCtx, err := config.GetCurrentContext()
		if err != nil {
			return err
		}
		uc, err := client.UserServiceClient(currentCtx)
		if err != nil {
			return err
		}
		devices, err := uc.ListWebAuthnDevices(context.Background(), connect.NewRequest(&ssov1.ListWebAuthnDevicesRequest{UserId: args[0]}))
		if err != nil {
			return fmt.Errorf("failed to list passkeys: %w", err)
		}
		if len(devices.Msg.GetDevices()) == 0 {
			fmt.Println("No passkeys registered.")
			return nil
		}
		for _, d := range devices.Msg.GetDevices() {
			fmt.Printf("%s  name=%q created=%s transports=%v\n", d.GetId(), d.GetName(), d.GetCreatedAt().AsTime().Format("2006-01-02"), d.GetTransports())
		}
		return nil
	},
}

var mfaPasskeyRemoveCmd = &cobra.Command{
	Use:   "remove [USER_ID_OR_EMAIL]",
	Short: "Remove a registered passkey by device ID",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		deviceID, _ := cmd.Flags().GetString("device")
		if deviceID == "" {
			return errors.New("--device is required")
		}
		currentCtx, err := config.GetCurrentContext()
		if err != nil {
			return err
		}
		uc, err := client.UserServiceClient(currentCtx)
		if err != nil {
			return err
		}
		_, err = uc.RemoveWebAuthnDevice(context.Background(), connect.NewRequest(&ssov1.RemoveWebAuthnDeviceRequest{
			UserId:   args[0],
			DeviceId: deviceID,
		}))
		if err != nil {
			return fmt.Errorf("failed to remove passkey: %w", err)
		}
		fmt.Printf("Passkey %s removed from %s.\n", deviceID, args[0])
		return nil
	},
}

// --- realm policy ---

var mfaPolicyCmd = &cobra.Command{
	Use:   "policy",
	Short: "Read or change the realm-wide MFA policy",
}

var mfaPolicyShowCmd = &cobra.Command{
	Use:   "show",
	Short: "Show the realm-wide MFA policy",
	RunE: func(cmd *cobra.Command, args []string) error {
		currentCtx, err := config.GetCurrentContext()
		if err != nil {
			return err
		}
		c, err := client.TwoFactorServiceClient(currentCtx)
		if err != nil {
			return err
		}
		resp, err := c.GetMFAPolicy(context.Background(), connect.NewRequest(&ssov1.GetMFAPolicyRequest{}))
		if err != nil {
			return fmt.Errorf("failed to read MFA policy: %w", err)
		}
		fmt.Printf("realm require_mfa: %t\n", resp.Msg.GetRequireMfa())
		return nil
	},
}

var mfaPolicySetCmd = &cobra.Command{
	Use:   "set",
	Short: "Set the realm-wide MFA policy",
	RunE: func(cmd *cobra.Command, args []string) error {
		required, _ := cmd.Flags().GetBool("require-mfa")
		currentCtx, err := config.GetCurrentContext()
		if err != nil {
			return err
		}
		c, err := client.TwoFactorServiceClient(currentCtx)
		if err != nil {
			return err
		}
		_, err = c.SetMFAPolicy(context.Background(), connect.NewRequest(&ssov1.SetMFAPolicyRequest{RequireMfa: required}))
		if err != nil {
			return fmt.Errorf("failed to update MFA policy: %w", err)
		}
		fmt.Printf("realm require_mfa set to %t.\n", required)
		if required {
			fmt.Println("Users without a TOTP factor will be sent to enrollment on their next login.")
		}
		return nil
	},
}

func init() {
	rootCmd.AddCommand(mfaCmd)
	mfaCmd.AddCommand(mfaStatusCmd)
	mfaCmd.AddCommand(mfaResetCmd)
	mfaCmd.AddCommand(mfaRequireCmd)
	mfaCmd.AddCommand(mfaTotpCmd)
	mfaCmd.AddCommand(mfaRecoveryCmd)
	mfaCmd.AddCommand(mfaListCmd)
	mfaCmd.AddCommand(mfaPasskeyCmd)
	mfaCmd.AddCommand(mfaPolicyCmd)

	mfaTotpCmd.AddCommand(mfaTotpEnrollCmd)
	mfaRecoveryCmd.AddCommand(mfaRecoveryGenerateCmd)
	mfaPasskeyCmd.AddCommand(mfaPasskeyListCmd)
	mfaPasskeyCmd.AddCommand(mfaPasskeyRemoveCmd)
	mfaPolicyCmd.AddCommand(mfaPolicyShowCmd)
	mfaPolicyCmd.AddCommand(mfaPolicySetCmd)

	mfaResetCmd.Flags().Bool("remove-passkeys", false, "Also delete registered WebAuthn devices")
	mfaResetCmd.Flags().BoolP("yes", "y", false, "Skip the confirmation prompt")
	mfaRequireCmd.Flags().Bool("off", false, "Clear the requirement instead of setting it")
	mfaTotpEnrollCmd.Flags().String("code", "", "TOTP code to confirm enrollment (prompts when omitted)")
	mfaPasskeyRemoveCmd.Flags().String("device", "", "WebAuthn device ID to remove")
	mfaPolicySetCmd.Flags().Bool("require-mfa", true, "Whether the realm requires MFA")
}
