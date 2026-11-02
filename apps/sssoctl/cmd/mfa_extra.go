package cmd

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"
	"syscall"

	"connectrpc.com/connect"
	"github.com/mdp/qrterminal"
	"github.com/pilab-dev/shadow-sso/apps/sssoctl/cmd/client"
	"github.com/pilab-dev/shadow-sso/apps/sssoctl/cmd/config"
	ssov1 "github.com/pilab-dev/shadow-sso/gen/proto/sso/v1"
	"github.com/pilab-dev/shadow-sso/gen/proto/sso/v1/ssov1connect"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

func twoFactorClient() (ssov1connect.TwoFactorServiceClient, error) {
	currentCtx, err := config.GetCurrentContext()
	if err != nil {
		return nil, err
	}
	return client.TwoFactorServiceClient(currentCtx)
}

func promptLine(label string) (string, error) {
	if !interactive() {
		return "", requireInteractive(label)
	}
	fmt.Print(label + ": ")
	value, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(value), nil
}

func promptPasswordLine(label string) (string, error) {
	if !interactive() {
		return "", requireInteractive(label)
	}
	fmt.Print(label + ": ")
	b, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Println()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

// --- HOTP ---

var mfaHotpCmd = &cobra.Command{Use: "hotp", Short: "Manage HOTP factors (self-service)"}

var mfaHotpEnrollCmd = &cobra.Command{
	Use:   "enroll",
	Short: "Enroll an HOTP factor for the authenticated account",
	RunE: func(cmd *cobra.Command, args []string) error {
		c, err := twoFactorClient()
		if err != nil {
			return err
		}
		setup, err := c.InitiateHOTPSetup(context.Background(), connect.NewRequest(&ssov1.InitiateHOTPSetupRequest{}))
		if err != nil {
			return fmt.Errorf("failed to start HOTP setup: %w", err)
		}
		fmt.Printf("HOTP secret: %s\nCounter: %d\n", setup.Msg.GetSecret(), setup.Msg.GetInitialCounter())
		qrterminal.GenerateHalfBlock(setup.Msg.GetQrCodeUri(), qrterminal.L, os.Stdout)
		code, _ := cmd.Flags().GetString("code")
		if code == "" {
			code, err = promptLine("HOTP code")
			if err != nil {
				return err
			}
		}
		resp, err := c.VerifyAndEnableHOTP(context.Background(), connect.NewRequest(&ssov1.VerifyAndEnableHOTPRequest{HotpCode: code}))
		if err != nil {
			return fmt.Errorf("failed to verify HOTP: %w", err)
		}
		fmt.Println("HOTP enabled.")
		for i, rc := range resp.Msg.GetRecoveryCodes() {
			fmt.Printf("  %d. %s\n", i+1, rc)
		}
		return nil
	},
}

// --- Email MFA ---

var mfaEmailCmd = &cobra.Command{Use: "email", Short: "Manage email MFA (self-service)"}

var mfaEmailEnrollCmd = &cobra.Command{
	Use:   "enroll",
	Short: "Enroll email MFA for the authenticated account",
	RunE: func(cmd *cobra.Command, args []string) error {
		c, err := twoFactorClient()
		if err != nil {
			return err
		}
		init, err := c.InitiateEmailMFASetup(context.Background(), connect.NewRequest(&ssov1.InitiateEmailMFASetupRequest{}))
		if err != nil {
			return fmt.Errorf("failed to start email MFA setup: %w", err)
		}
		fmt.Println(init.Msg.GetMessage())
		otp, _ := cmd.Flags().GetString("otp")
		if otp == "" {
			otp, err = promptLine("Email OTP")
			if err != nil {
				return err
			}
		}
		resp, err := c.VerifyAndEnableEmailMFA(context.Background(), connect.NewRequest(&ssov1.VerifyAndEnableEmailMFARequest{EmailOtp: otp}))
		if err != nil {
			return fmt.Errorf("failed to verify email MFA: %w", err)
		}
		fmt.Println("Email MFA enabled.")
		for i, rc := range resp.Msg.GetRecoveryCodes() {
			fmt.Printf("  %d. %s\n", i+1, rc)
		}
		return nil
	},
}

// --- Push MFA ---

var mfaPushCmd = &cobra.Command{Use: "push", Short: "Manage push MFA (self-service)"}

var mfaPushEnrollCmd = &cobra.Command{
	Use:   "enroll",
	Short: "Register a device token and enable push MFA",
	RunE: func(cmd *cobra.Command, args []string) error {
		token, _ := cmd.Flags().GetString("device-token")
		if token == "" {
			return requireInteractive("push MFA enrollment", "--device-token")
		}
		c, err := twoFactorClient()
		if err != nil {
			return err
		}
		if _, err := c.InitiatePushMFASetup(context.Background(), connect.NewRequest(&ssov1.InitiatePushMFASetupRequest{DeviceToken: token})); err != nil {
			return fmt.Errorf("failed to register push device: %w", err)
		}
		resp, err := c.VerifyAndEnablePushMFA(context.Background(), connect.NewRequest(&ssov1.VerifyAndEnablePushMFARequest{}))
		if err != nil {
			return fmt.Errorf("failed to enable push MFA: %w", err)
		}
		fmt.Println("Push MFA enabled.")
		for i, rc := range resp.Msg.GetRecoveryCodes() {
			fmt.Printf("  %d. %s\n", i+1, rc)
		}
		return nil
	},
}

var mfaPushRegisterCmd = &cobra.Command{
	Use:   "register-device",
	Short: "Register a Firebase device token",
	RunE: func(cmd *cobra.Command, args []string) error {
		token, _ := cmd.Flags().GetString("device-token")
		if token == "" {
			return requireInteractive("push device registration", "--device-token")
		}
		c, err := twoFactorClient()
		if err != nil {
			return err
		}
		resp, err := c.RegisterPushDevice(context.Background(), connect.NewRequest(&ssov1.RegisterPushDeviceRequest{DeviceToken: token}))
		if err != nil {
			return fmt.Errorf("failed to register device: %w", err)
		}
		fmt.Println(resp.Msg.GetMessage())
		return nil
	},
}

var mfaPushUnregisterCmd = &cobra.Command{
	Use:   "unregister-device",
	Short: "Unregister a Firebase device token",
	RunE: func(cmd *cobra.Command, args []string) error {
		token, _ := cmd.Flags().GetString("device-token")
		if token == "" {
			return requireInteractive("push device removal", "--device-token")
		}
		c, err := twoFactorClient()
		if err != nil {
			return err
		}
		resp, err := c.UnregisterPushDevice(context.Background(), connect.NewRequest(&ssov1.UnregisterPushDeviceRequest{DeviceToken: token}))
		if err != nil {
			return fmt.Errorf("failed to unregister device: %w", err)
		}
		fmt.Println(resp.Msg.GetMessage())
		return nil
	},
}

var mfaPushRespondCmd = &cobra.Command{
	Use:   "respond",
	Short: "Approve or deny a push challenge",
	RunE: func(cmd *cobra.Command, args []string) error {
		id, _ := cmd.Flags().GetString("challenge-id")
		response, _ := cmd.Flags().GetString("response")
		if id == "" || response == "" {
			return requireInteractive("push challenge response", "--challenge-id --response")
		}
		c, err := twoFactorClient()
		if err != nil {
			return err
		}
		resp, err := c.RespondToPushChallenge(context.Background(), connect.NewRequest(&ssov1.RespondToPushChallengeRequest{ChallengeId: id, Response: response}))
		if err != nil {
			return fmt.Errorf("failed to respond to challenge: %w", err)
		}
		fmt.Println(resp.Msg.GetStatus())
		return nil
	},
}

var mfaPushStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Get a push challenge's status",
	RunE: func(cmd *cobra.Command, args []string) error {
		id, _ := cmd.Flags().GetString("challenge-id")
		if id == "" {
			return requireInteractive("push challenge status", "--challenge-id")
		}
		c, err := twoFactorClient()
		if err != nil {
			return err
		}
		resp, err := c.GetPushChallengeStatus(context.Background(), connect.NewRequest(&ssov1.GetPushChallengeStatusRequest{ChallengeId: id}))
		if err != nil {
			return fmt.Errorf("failed to get challenge status: %w", err)
		}
		fmt.Println(resp.Msg.GetStatus())
		return nil
	},
}

// --- generic challenge ---

var mfaChallengeCmd = &cobra.Command{Use: "challenge", Short: "Send and verify MFA challenges (self-service)"}

var mfaChallengeSendCmd = &cobra.Command{
	Use:   "send",
	Short: "Send an MFA challenge using the configured method",
	RunE: func(cmd *cobra.Command, args []string) error {
		c, err := twoFactorClient()
		if err != nil {
			return err
		}
		resp, err := c.SendMFAChallenge(context.Background(), connect.NewRequest(&ssov1.SendMFAChallengeRequest{}))
		if err != nil {
			return fmt.Errorf("failed to send challenge: %w", err)
		}
		fmt.Printf("method=%s message=%s counter=%d challenge_id=%s\n",
			resp.Msg.GetMethod(), resp.Msg.GetMessage(), resp.Msg.GetCounter(), resp.Msg.GetChallengeId())
		return nil
	},
}

var mfaChallengeVerifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Verify an MFA challenge code",
	RunE: func(cmd *cobra.Command, args []string) error {
		code, _ := cmd.Flags().GetString("code")
		counter, _ := cmd.Flags().GetUint64("counter")
		if code == "" {
			return requireInteractive("challenge verification", "--code")
		}
		c, err := twoFactorClient()
		if err != nil {
			return err
		}
		resp, err := c.VerifyMFAChallenge(context.Background(), connect.NewRequest(&ssov1.VerifyMFAChallengeRequest{Code: code, Counter: counter}))
		if err != nil {
			return fmt.Errorf("failed to verify challenge: %w", err)
		}
		fmt.Printf("verified=%t\n", resp.Msg.GetVerified())
		return nil
	},
}

// --- self-service disable ---

var mfaDisableCmd = &cobra.Command{
	Use:   "disable",
	Short: "Disable 2FA for the authenticated account (requires password or code)",
	RunE: func(cmd *cobra.Command, args []string) error {
		secret, _ := cmd.Flags().GetString("password-or-code")
		var err error
		if secret == "" {
			secret, err = promptPasswordLine("Password or 2FA code")
			if err != nil {
				return err
			}
		}
		c, err := twoFactorClient()
		if err != nil {
			return err
		}
		_, err = c.Disable2FA(context.Background(), connect.NewRequest(&ssov1.Disable2FARequest{PasswordOr_2FaCode: secret}))
		if err != nil {
			return fmt.Errorf("failed to disable 2FA: %w", err)
		}
		fmt.Println("2FA disabled for the authenticated account.")
		return nil
	},
}

func init() {
	mfaCmd.AddCommand(mfaHotpCmd)
	mfaHotpCmd.AddCommand(mfaHotpEnrollCmd)
	mfaCmd.AddCommand(mfaEmailCmd)
	mfaEmailCmd.AddCommand(mfaEmailEnrollCmd)
	mfaCmd.AddCommand(mfaPushCmd)
	mfaPushCmd.AddCommand(mfaPushEnrollCmd)
	mfaPushCmd.AddCommand(mfaPushRegisterCmd)
	mfaPushCmd.AddCommand(mfaPushUnregisterCmd)
	mfaPushCmd.AddCommand(mfaPushRespondCmd)
	mfaPushCmd.AddCommand(mfaPushStatusCmd)
	mfaCmd.AddCommand(mfaChallengeCmd)
	mfaChallengeCmd.AddCommand(mfaChallengeSendCmd)
	mfaChallengeCmd.AddCommand(mfaChallengeVerifyCmd)
	mfaCmd.AddCommand(mfaDisableCmd)

	mfaHotpEnrollCmd.Flags().String("code", "", "Initial HOTP code (prompts when omitted)")
	mfaEmailEnrollCmd.Flags().String("otp", "", "Email OTP (prompts when omitted)")
	mfaPushEnrollCmd.Flags().String("device-token", "", "Firebase device token")
	mfaPushRegisterCmd.Flags().String("device-token", "", "Firebase device token")
	mfaPushUnregisterCmd.Flags().String("device-token", "", "Firebase device token")
	mfaPushRespondCmd.Flags().String("challenge-id", "", "Push challenge ID")
	mfaPushRespondCmd.Flags().String("response", "approve", "approve or deny")
	mfaPushStatusCmd.Flags().String("challenge-id", "", "Push challenge ID")
	mfaChallengeVerifyCmd.Flags().String("code", "", "MFA code")
	mfaChallengeVerifyCmd.Flags().Uint64("counter", 0, "HOTP counter")
	mfaDisableCmd.Flags().String("password-or-code", "", "Current password, TOTP code or recovery code")
}
