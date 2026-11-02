package cmd

import (
	"context"
	"fmt"

	"connectrpc.com/connect"
	ssov1 "github.com/pilab-dev/shadow-sso/gen/proto/sso/v1"
	"github.com/spf13/cobra"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// --- MFA method records (UserService) ---

var userMfaMethodCmd = &cobra.Command{Use: "mfa-method", Short: "Manage stored MFA method records"}

var userMfaMethodListCmd = &cobra.Command{
	Use:   "list [USER_ID_OR_EMAIL]",
	Short: "List stored MFA method records",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		uc, err := mustUserClient()
		if err != nil {
			return err
		}
		resp, err := uc.ListMfaMethods(context.Background(), connect.NewRequest(&ssov1.ListMfaMethodsRequest{UserId: args[0]}))
		if err != nil {
			return fmt.Errorf("failed to list MFA methods: %w", err)
		}
		if len(resp.Msg.GetMethods()) == 0 {
			fmt.Println("No MFA method records.")
			return nil
		}
		for _, m := range resp.Msg.GetMethods() {
			fmt.Printf("%s  type=%s verified=%t name=%q\n", m.GetId(), m.GetType(), m.GetVerified(), m.GetName())
		}
		return nil
	},
}

var userMfaMethodAddCmd = &cobra.Command{
	Use:   "add [USER_ID_OR_EMAIL]",
	Short: "Add an MFA method record",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		methodType, _ := cmd.Flags().GetString("type")
		secret, _ := cmd.Flags().GetString("secret")
		name, _ := cmd.Flags().GetString("name")
		verified, _ := cmd.Flags().GetBool("verified")
		if methodType == "" {
			return requireInteractive("MFA method add", "--type")
		}
		uc, err := mustUserClient()
		if err != nil {
			return err
		}
		resp, err := uc.AddMfaMethod(context.Background(), connect.NewRequest(&ssov1.AddMfaMethodRequest{
			UserId: args[0],
			Method: &ssov1.MfaMethod{
				Type:     parseMfaMethodType(methodType),
				Secret:   secret,
				Name:     name,
				Verified: verified,
			},
		}))
		if err != nil {
			return fmt.Errorf("failed to add MFA method: %w", err)
		}
		fmt.Printf("Added MFA method %s (type=%s).\n", resp.Msg.GetMethod().GetId(), resp.Msg.GetMethod().GetType())
		return nil
	},
}

var userMfaMethodGetCmd = &cobra.Command{
	Use:   "get [USER_ID_OR_EMAIL] [METHOD_ID]",
	Short: "Get an MFA method record",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		uc, err := mustUserClient()
		if err != nil {
			return err
		}
		resp, err := uc.GetMfaMethod(context.Background(), connect.NewRequest(&ssov1.GetMfaMethodRequest{UserId: args[0], MethodId: args[1]}))
		if err != nil {
			return fmt.Errorf("failed to get MFA method: %w", err)
		}
		return printProtoJSON(resp.Msg.GetMethod())
	},
}

var userMfaMethodVerifyCmd = &cobra.Command{
	Use:   "verify [USER_ID_OR_EMAIL] [METHOD_ID]",
	Short: "Mark an MFA method record as verified",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		uc, err := mustUserClient()
		if err != nil {
			return err
		}
		_, err = uc.VerifyMfaMethod(context.Background(), connect.NewRequest(&ssov1.VerifyMfaMethodRequest{UserId: args[0], MethodId: args[1]}))
		if err != nil {
			return fmt.Errorf("failed to verify MFA method: %w", err)
		}
		fmt.Println("MFA method verified.")
		return nil
	},
}

var userMfaMethodRemoveCmd = &cobra.Command{
	Use:   "remove [USER_ID_OR_EMAIL] [METHOD_ID]",
	Short: "Remove an MFA method record",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		uc, err := mustUserClient()
		if err != nil {
			return err
		}
		_, err = uc.RemoveMfaMethod(context.Background(), connect.NewRequest(&ssov1.RemoveMfaMethodRequest{UserId: args[0], MethodId: args[1]}))
		if err != nil {
			return fmt.Errorf("failed to remove MFA method: %w", err)
		}
		fmt.Println("MFA method removed.")
		return nil
	},
}

// --- WebAuthn device records (UserService) ---

var userWebAuthnCmd = &cobra.Command{Use: "webauthn", Short: "Manage stored WebAuthn device records"}

var userWebAuthnListCmd = &cobra.Command{
	Use:   "list [USER_ID_OR_EMAIL]",
	Short: "List WebAuthn devices",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		uc, err := mustUserClient()
		if err != nil {
			return err
		}
		resp, err := uc.ListWebAuthnDevices(context.Background(), connect.NewRequest(&ssov1.ListWebAuthnDevicesRequest{UserId: args[0]}))
		if err != nil {
			return fmt.Errorf("failed to list devices: %w", err)
		}
		if len(resp.Msg.GetDevices()) == 0 {
			fmt.Println("No WebAuthn devices.")
			return nil
		}
		for _, d := range resp.Msg.GetDevices() {
			fmt.Printf("%s  name=%q credential=%s counter=%d transports=%v\n",
				d.GetId(), d.GetName(), d.GetCredentialId(), d.GetCounter(), d.GetTransports())
		}
		return nil
	},
}

var userWebAuthnGetCmd = &cobra.Command{
	Use:   "get [USER_ID_OR_EMAIL] [DEVICE_ID]",
	Short: "Get a WebAuthn device",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		uc, err := mustUserClient()
		if err != nil {
			return err
		}
		resp, err := uc.GetWebAuthnDevice(context.Background(), connect.NewRequest(&ssov1.GetWebAuthnDeviceRequest{UserId: args[0], DeviceId: args[1]}))
		if err != nil {
			return fmt.Errorf("failed to get device: %w", err)
		}
		return printProtoJSON(resp.Msg.GetDevice())
	},
}

var userWebAuthnRemoveCmd = &cobra.Command{
	Use:   "remove [USER_ID_OR_EMAIL] [DEVICE_ID]",
	Short: "Remove a WebAuthn device",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		uc, err := mustUserClient()
		if err != nil {
			return err
		}
		_, err = uc.RemoveWebAuthnDevice(context.Background(), connect.NewRequest(&ssov1.RemoveWebAuthnDeviceRequest{UserId: args[0], DeviceId: args[1]}))
		if err != nil {
			return fmt.Errorf("failed to remove device: %w", err)
		}
		fmt.Println("WebAuthn device removed.")
		return nil
	},
}

var userWebAuthnCounterCmd = &cobra.Command{
	Use:   "set-counter [USER_ID_OR_EMAIL] [DEVICE_ID]",
	Short: "Overwrite a device's signature counter",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		counter, _ := cmd.Flags().GetInt32("counter")
		uc, err := mustUserClient()
		if err != nil {
			return err
		}
		_, err = uc.UpdateWebAuthnDeviceCounter(context.Background(), connect.NewRequest(&ssov1.UpdateWebAuthnDeviceCounterRequest{
			UserId: args[0], DeviceId: args[1], NewCounter: counter,
		}))
		if err != nil {
			return fmt.Errorf("failed to update counter: %w", err)
		}
		fmt.Println("Counter updated.")
		return nil
	},
}

var userWebAuthnAddCmd = &cobra.Command{
	Use:   "add [USER_ID_OR_EMAIL]",
	Short: "Add a WebAuthn device record directly (no attestation verification)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		credentialID, _ := cmd.Flags().GetString("credential-id")
		publicKey, _ := cmd.Flags().GetString("public-key")
		name, _ := cmd.Flags().GetString("name")
		if credentialID == "" || publicKey == "" {
			return requireInteractive("WebAuthn device add", "--credential-id --public-key")
		}
		uc, err := mustUserClient()
		if err != nil {
			return err
		}
		transports, _ := cmd.Flags().GetStringSlice("transports")
		resp, err := uc.AddWebAuthnDevice(context.Background(), connect.NewRequest(&ssov1.AddWebAuthnDeviceRequest{
			UserId: args[0],
			Device: &ssov1.WebAuthnDevice{
				Name:         name,
				CredentialId: credentialID,
				PublicKey:    publicKey,
				Transports:   transports,
				CreatedAt:    timestamppb.Now(),
			},
		}))
		if err != nil {
			return fmt.Errorf("failed to add device: %w", err)
		}
		fmt.Printf("Added WebAuthn device %s.\n", resp.Msg.GetDevice().GetId())
		return nil
	},
}

// --- legacy TOTP setup ---

var userTotpCmd = &cobra.Command{Use: "totp", Short: "Legacy TOTP setup (prefer 'mfa totp enroll')"}

var userTotpSetupCmd = &cobra.Command{
	Use:   "setup [USER_ID_OR_EMAIL]",
	Short: "Start TOTP setup and return the secret",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		uc, err := mustUserClient()
		if err != nil {
			return err
		}
		resp, err := uc.SetupTotp(context.Background(), connect.NewRequest(&ssov1.SetupTotpRequest{UserId: args[0]}))
		if err != nil {
			return fmt.Errorf("failed to setup TOTP: %w", err)
		}
		fmt.Printf("secret=%s\nqr=%s\n", resp.Msg.GetSecret(), resp.Msg.GetQrCodeUri())
		return nil
	},
}

var userTotpVerifyCmd = &cobra.Command{
	Use:   "verify [USER_ID_OR_EMAIL]",
	Short: "Verify a TOTP code and enable 2FA",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		code, _ := cmd.Flags().GetString("code")
		if code == "" {
			return requireInteractive("TOTP verification", "--code")
		}
		uc, err := mustUserClient()
		if err != nil {
			return err
		}
		resp, err := uc.VerifyTotpSetup(context.Background(), connect.NewRequest(&ssov1.VerifyTotpSetupRequest{UserId: args[0], Token: code}))
		if err != nil {
			return fmt.Errorf("failed to verify TOTP: %w", err)
		}
		fmt.Printf("verified=%t\n", resp.Msg.GetVerified())
		return nil
	},
}

// --- password hash override ---

var userPasswordHashCmd = &cobra.Command{
	Use:   "set-password-hash [USER_ID_OR_EMAIL]",
	Short: "Set a pre-computed password hash (advanced; use set-password normally)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		hash, _ := cmd.Flags().GetString("hash")
		if hash == "" {
			return requireInteractive("set-password-hash", "--hash")
		}
		uc, err := mustUserClient()
		if err != nil {
			return err
		}
		_, err = uc.UpdateUserPassword(context.Background(), connect.NewRequest(&ssov1.UpdateUserPasswordRequest{UserId: args[0], NewPasswordHash: hash}))
		if err != nil {
			return fmt.Errorf("failed to update password hash: %w", err)
		}
		fmt.Println("Password hash updated.")
		return nil
	},
}

func init() {
	userCmd.AddCommand(userMfaMethodCmd)
	userMfaMethodCmd.AddCommand(userMfaMethodListCmd, userMfaMethodAddCmd, userMfaMethodGetCmd, userMfaMethodVerifyCmd, userMfaMethodRemoveCmd)
	userMfaMethodAddCmd.Flags().String("type", "", "Method type: totp, sms, email, webauthn, push")
	userMfaMethodAddCmd.Flags().String("secret", "", "Method secret (TOTP/HOTP)")
	userMfaMethodAddCmd.Flags().String("name", "", "Human-readable name")
	userMfaMethodAddCmd.Flags().Bool("verified", false, "Mark the method verified")

	userCmd.AddCommand(userWebAuthnCmd)
	userWebAuthnCmd.AddCommand(userWebAuthnListCmd, userWebAuthnGetCmd, userWebAuthnRemoveCmd, userWebAuthnCounterCmd, userWebAuthnAddCmd)
	userWebAuthnCounterCmd.Flags().Int32("counter", 0, "New signature counter")
	userWebAuthnAddCmd.Flags().String("credential-id", "", "Base64url credential ID")
	userWebAuthnAddCmd.Flags().String("public-key", "", "COSE public key")
	userWebAuthnAddCmd.Flags().String("name", "", "Device name")
	userWebAuthnAddCmd.Flags().StringSlice("transports", nil, "Authenticator transports")

	userCmd.AddCommand(userTotpCmd)
	userTotpCmd.AddCommand(userTotpSetupCmd, userTotpVerifyCmd)
	userTotpVerifyCmd.Flags().String("code", "", "TOTP code")

	userCmd.AddCommand(userPasswordHashCmd)
	userPasswordHashCmd.Flags().String("hash", "", "Pre-computed password hash")
}
