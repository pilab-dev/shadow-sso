package cmd

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"
	"syscall"

	"connectrpc.com/connect"
	"github.com/pilab-dev/shadow-sso/apps/sssoctl/cmd/client"
	"github.com/pilab-dev/shadow-sso/apps/sssoctl/cmd/config"
	ssov1 "github.com/pilab-dev/shadow-sso/gen/proto/sso/v1"
	"github.com/pilab-dev/shadow-sso/gen/proto/sso/v1/ssov1connect"
	"github.com/spf13/cobra"
	"golang.org/x/term"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

func mustUserClient() (ssov1connect.UserServiceClient, error) {
	currentCtx, err := config.GetCurrentContext()
	if err != nil {
		return nil, err
	}
	return client.UserServiceClient(currentCtx)
}

func printProtoJSON(msg proto.Message) error {
	out, err := protojson.MarshalOptions{Indent: "  ", UseProtoNames: true, EmitUnpopulated: false}.Marshal(msg)
	if err != nil {
		return err
	}
	fmt.Println(string(out))
	return nil
}

func promptSecret(label string) (string, error) {
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

// --- user update / delete / password ---

var userUpdateCmd = &cobra.Command{
	Use:   "update [USER_ID_OR_EMAIL]",
	Short: "Update a user's email, name or realm roles",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		uc, err := mustUserClient()
		if err != nil {
			return err
		}
		req := &ssov1.UpdateUserRequest{UserId: args[0]}
		req.Email, _ = cmd.Flags().GetString("email")
		req.FirstName, _ = cmd.Flags().GetString("first-name")
		req.LastName, _ = cmd.Flags().GetString("last-name")
		if cmd.Flags().Changed("role") {
			req.Roles, _ = cmd.Flags().GetStringArray("role")
		}
		resp, err := uc.UpdateUser(context.Background(), connect.NewRequest(req))
		if err != nil {
			return fmt.Errorf("failed to update user: %w", err)
		}
		return printProtoJSON(resp.Msg.GetUser())
	},
}

var userDeleteCmd = &cobra.Command{
	Use:   "delete [USER_ID_OR_EMAIL]",
	Short: "Delete a user account",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		yes, _ := cmd.Flags().GetBool("yes")
		if !yes {
			if err := requireInteractive("user deletion", "--yes"); err != nil {
				return err
			}
			fmt.Printf("Delete user %s permanently? Type 'yes' to confirm: ", args[0])
			answer, _ := bufio.NewReader(os.Stdin).ReadString('\n')
			if strings.TrimSpace(strings.ToLower(answer)) != "yes" {
				fmt.Println("Aborted.")
				return nil
			}
		}
		uc, err := mustUserClient()
		if err != nil {
			return err
		}
		_, err = uc.DeleteUser(context.Background(), connect.NewRequest(&ssov1.DeleteUserRequest{UserId: args[0]}))
		if err != nil {
			return fmt.Errorf("failed to delete user: %w", err)
		}
		fmt.Printf("User %s deleted.\n", args[0])
		return nil
	},
}

var userSetPasswordCmd = &cobra.Command{
	Use:   "set-password [USER_ID_OR_EMAIL]",
	Short: "Set a user's password (admin, no old password required)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		password, _ := cmd.Flags().GetString("password")
		if password == "" {
			if !interactive() {
				return requireInteractive("set-password", "--password")
			}
			var err error
			password, err = promptSecret("New password")
			if err != nil {
				return err
			}
			confirm, err := promptSecret("Confirm password")
			if err != nil {
				return err
			}
			if password != confirm {
				return fmt.Errorf("passwords do not match")
			}
		}
		uc, err := mustUserClient()
		if err != nil {
			return err
		}
		_, err = uc.ChangePassword(context.Background(), connect.NewRequest(&ssov1.ChangePasswordRequest{
			UserId:      args[0],
			NewPassword: password,
		}))
		if err != nil {
			return fmt.Errorf("failed to set password: %w", err)
		}
		fmt.Printf("Password updated for %s.\n", args[0])
		return nil
	},
}

var userVerifyEmailCmd = &cobra.Command{
	Use:   "verify-email [USER_ID_OR_EMAIL]",
	Short: "Mark a user's email as verified",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		uc, err := mustUserClient()
		if err != nil {
			return err
		}
		_, err = uc.SetEmailAsVerified(context.Background(), connect.NewRequest(&ssov1.SetEmailAsVerifiedRequest{UserId: args[0]}))
		if err != nil {
			return fmt.Errorf("failed to mark email verified: %w", err)
		}
		fmt.Printf("Email marked verified for %s.\n", args[0])
		return nil
	},
}

// --- failed login attempts ---

var userFailedCmd = &cobra.Command{
	Use:   "failed-attempts",
	Short: "Inspect or reset failed login counters",
}

var userFailedResetCmd = &cobra.Command{
	Use:   "reset [USER_ID_OR_EMAIL]",
	Short: "Reset a user's failed login counter",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		uc, err := mustUserClient()
		if err != nil {
			return err
		}
		_, err = uc.ResetFailedLoginAttempts(context.Background(), connect.NewRequest(&ssov1.ResetFailedLoginAttemptsRequest{UserId: args[0]}))
		if err != nil {
			return fmt.Errorf("failed to reset failed attempts: %w", err)
		}
		fmt.Printf("Failed login counter reset for %s.\n", args[0])
		return nil
	},
}

var userFailedIncrementCmd = &cobra.Command{
	Use:   "increment [USER_ID_OR_EMAIL]",
	Short: "Increment a user's failed login counter (testing/lockout)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		uc, err := mustUserClient()
		if err != nil {
			return err
		}
		resp, err := uc.IncrementFailedLoginAttempts(context.Background(), connect.NewRequest(&ssov1.IncrementFailedLoginAttemptsRequest{UserId: args[0]}))
		if err != nil {
			return fmt.Errorf("failed to increment failed attempts: %w", err)
		}
		fmt.Printf("Failed login attempts for %s: %d\n", args[0], resp.Msg.GetCurrentAttempts())
		return nil
	},
}

// --- email verification / password reset ---

var userEmailCmd = &cobra.Command{
	Use:   "email",
	Short: "Email verification helpers",
}

var userEmailSendCmd = &cobra.Command{
	Use:   "send-verification [USER_ID_OR_EMAIL]",
	Short: "Send an email verification message",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		uc, err := mustUserClient()
		if err != nil {
			return err
		}
		_, err = uc.SendEmailVerification(context.Background(), connect.NewRequest(&ssov1.SendEmailVerificationRequest{UserId: args[0]}))
		if err != nil {
			return fmt.Errorf("failed to send verification: %w", err)
		}
		fmt.Println("Verification email sent.")
		return nil
	},
}

var userEmailVerifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Verify an email with a token",
	RunE: func(cmd *cobra.Command, args []string) error {
		token, _ := cmd.Flags().GetString("token")
		if token == "" {
			return requireInteractive("email verification", "--token")
		}
		uc, err := mustUserClient()
		if err != nil {
			return err
		}
		resp, err := uc.VerifyEmail(context.Background(), connect.NewRequest(&ssov1.VerifyEmailRequest{Token: token}))
		if err != nil {
			return fmt.Errorf("failed to verify email: %w", err)
		}
		fmt.Printf("success=%t %s %s\n", resp.Msg.GetSuccess(), resp.Msg.GetMessage(), resp.Msg.GetError())
		return nil
	},
}

var userPasswordResetCmd = &cobra.Command{
	Use:   "password-reset",
	Short: "Password reset helpers",
}

var userPasswordResetRequestCmd = &cobra.Command{
	Use:   "request",
	Short: "Request a password reset email",
	RunE: func(cmd *cobra.Command, args []string) error {
		email, _ := cmd.Flags().GetString("email")
		if email == "" {
			return requireInteractive("password reset request", "--email")
		}
		uc, err := mustUserClient()
		if err != nil {
			return err
		}
		resp, err := uc.RequestPasswordReset(context.Background(), connect.NewRequest(&ssov1.RequestPasswordResetRequest{Email: email}))
		if err != nil {
			return fmt.Errorf("failed to request password reset: %w", err)
		}
		fmt.Printf("success=%t %s\n", resp.Msg.GetSuccess(), resp.Msg.GetMessage())
		return nil
	},
}

var userPasswordResetConsumeCmd = &cobra.Command{
	Use:   "consume",
	Short: "Complete a password reset with a token",
	RunE: func(cmd *cobra.Command, args []string) error {
		token, _ := cmd.Flags().GetString("token")
		password, _ := cmd.Flags().GetString("password")
		if token == "" || password == "" {
			return requireInteractive("password reset", "--token --password")
		}
		uc, err := mustUserClient()
		if err != nil {
			return err
		}
		resp, err := uc.ResetPassword(context.Background(), connect.NewRequest(&ssov1.ResetPasswordRequest{Token: token, NewPassword: password}))
		if err != nil {
			return fmt.Errorf("failed to reset password: %w", err)
		}
		fmt.Printf("success=%t %s %s\n", resp.Msg.GetSuccess(), resp.Msg.GetMessage(), resp.Msg.GetError())
		return nil
	},
}

// --- phone verification ---

var userPhoneCmd = &cobra.Command{
	Use:   "phone",
	Short: "Phone number and verification helpers",
}

var userPhoneSetCmd = &cobra.Command{
	Use:   "set [USER_ID_OR_EMAIL]",
	Short: "Set a user's phone number",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		phone, _ := cmd.Flags().GetString("number")
		if phone == "" {
			return requireInteractive("phone set", "--number")
		}
		uc, err := mustUserClient()
		if err != nil {
			return err
		}
		_, err = uc.SetPhoneNumber(context.Background(), connect.NewRequest(&ssov1.SetPhoneNumberRequest{UserId: args[0], PhoneNumber: phone}))
		if err != nil {
			return fmt.Errorf("failed to set phone number: %w", err)
		}
		fmt.Println("Phone number updated.")
		return nil
	},
}

var userPhoneSendCmd = &cobra.Command{
	Use:   "send-otp [USER_ID_OR_EMAIL]",
	Short: "Send a phone verification OTP",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		uc, err := mustUserClient()
		if err != nil {
			return err
		}
		resp, err := uc.SendPhoneVerificationOtp(context.Background(), connect.NewRequest(&ssov1.SendPhoneVerificationOtpRequest{UserId: args[0]}))
		if err != nil {
			return fmt.Errorf("failed to send phone OTP: %w", err)
		}
		fmt.Printf("success=%t %s %s\n", resp.Msg.GetSuccess(), resp.Msg.GetMessage(), resp.Msg.GetError())
		return nil
	},
}

var userPhoneVerifyCmd = &cobra.Command{
	Use:   "verify [USER_ID_OR_EMAIL]",
	Short: "Verify a phone number with an OTP",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		otp, _ := cmd.Flags().GetString("otp")
		if otp == "" {
			return requireInteractive("phone verification", "--otp")
		}
		uc, err := mustUserClient()
		if err != nil {
			return err
		}
		resp, err := uc.VerifyPhoneNumber(context.Background(), connect.NewRequest(&ssov1.VerifyPhoneNumberRequest{UserId: args[0], Otp: otp}))
		if err != nil {
			return fmt.Errorf("failed to verify phone: %w", err)
		}
		fmt.Printf("success=%t %s %s\n", resp.Msg.GetSuccess(), resp.Msg.GetMessage(), resp.Msg.GetError())
		return nil
	},
}

// --- login OTP ---

var userLoginOtpCmd = &cobra.Command{
	Use:   "login-otp",
	Short: "Send and verify login OTPs",
}

var userLoginOtpSendCmd = &cobra.Command{
	Use:   "send [USER_ID_OR_EMAIL]",
	Short: "Send a login OTP via SMS or email",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		method, _ := cmd.Flags().GetString("method")
		uc, err := mustUserClient()
		if err != nil {
			return err
		}
		switch strings.ToLower(method) {
		case "sms":
			resp, err := uc.SendSmsOtp(context.Background(), connect.NewRequest(&ssov1.SendSmsOtpRequest{UserId: args[0]}))
			if err != nil {
				return fmt.Errorf("failed to send SMS OTP: %w", err)
			}
			fmt.Printf("success=%t %s %s\n", resp.Msg.GetSuccess(), resp.Msg.GetMessage(), resp.Msg.GetError())
		case "email":
			resp, err := uc.SendEmailOtp(context.Background(), connect.NewRequest(&ssov1.SendEmailOtpRequest{UserId: args[0]}))
			if err != nil {
				return fmt.Errorf("failed to send email OTP: %w", err)
			}
			fmt.Printf("success=%t %s %s\n", resp.Msg.GetSuccess(), resp.Msg.GetMessage(), resp.Msg.GetError())
		default:
			return fmt.Errorf("--method must be sms or email")
		}
		return nil
	},
}

var userLoginOtpVerifyCmd = &cobra.Command{
	Use:   "verify [USER_ID_OR_EMAIL]",
	Short: "Verify a login OTP",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		otp, _ := cmd.Flags().GetString("otp")
		method, _ := cmd.Flags().GetString("method")
		if otp == "" {
			return requireInteractive("login OTP verification", "--otp")
		}
		uc, err := mustUserClient()
		if err != nil {
			return err
		}
		resp, err := uc.VerifyLoginOtp(context.Background(), connect.NewRequest(&ssov1.VerifyLoginOtpRequest{
			UserId:     args[0],
			Otp:        otp,
			MethodType: parseMfaMethodType(method),
		}))
		if err != nil {
			return fmt.Errorf("failed to verify login OTP: %w", err)
		}
		fmt.Printf("success=%t %s\n", resp.Msg.GetSuccess(), resp.Msg.GetError())
		return nil
	},
}

func parseMfaMethodType(value string) ssov1.MfaMethodType {
	switch strings.ToLower(value) {
	case "totp":
		return ssov1.MfaMethodType_MFA_METHOD_TYPE_TOTP
	case "sms":
		return ssov1.MfaMethodType_MFA_METHOD_TYPE_SMS
	case "email":
		return ssov1.MfaMethodType_MFA_METHOD_TYPE_EMAIL
	case "webauthn":
		return ssov1.MfaMethodType_MFA_METHOD_TYPE_WEBAUTHN
	case "push":
		return ssov1.MfaMethodType_MFA_METHOD_TYPE_PUSH
	default:
		return ssov1.MfaMethodType_MFA_METHOD_TYPE_UNSPECIFIED
	}
}

func init() {
	userCmd.AddCommand(userUpdateCmd)
	userCmd.AddCommand(userDeleteCmd)
	userCmd.AddCommand(userSetPasswordCmd)
	userCmd.AddCommand(userVerifyEmailCmd)
	userCmd.AddCommand(userFailedCmd)
	userFailedCmd.AddCommand(userFailedResetCmd)
	userFailedCmd.AddCommand(userFailedIncrementCmd)
	userCmd.AddCommand(userEmailCmd)
	userEmailCmd.AddCommand(userEmailSendCmd)
	userEmailCmd.AddCommand(userEmailVerifyCmd)
	userCmd.AddCommand(userPasswordResetCmd)
	userPasswordResetCmd.AddCommand(userPasswordResetRequestCmd)
	userPasswordResetCmd.AddCommand(userPasswordResetConsumeCmd)
	userCmd.AddCommand(userPhoneCmd)
	userPhoneCmd.AddCommand(userPhoneSetCmd)
	userPhoneCmd.AddCommand(userPhoneSendCmd)
	userPhoneCmd.AddCommand(userPhoneVerifyCmd)
	userCmd.AddCommand(userLoginOtpCmd)
	userLoginOtpCmd.AddCommand(userLoginOtpSendCmd)
	userLoginOtpCmd.AddCommand(userLoginOtpVerifyCmd)

	userUpdateCmd.Flags().String("email", "", "New email address")
	userUpdateCmd.Flags().String("first-name", "", "New first name")
	userUpdateCmd.Flags().String("last-name", "", "New last name")
	userUpdateCmd.Flags().StringArray("role", nil, "Realm role (repeatable; replaces the role list)")
	userDeleteCmd.Flags().BoolP("yes", "y", false, "Skip the confirmation prompt")
	userSetPasswordCmd.Flags().String("password", "", "New password (prompts when omitted and interactive)")
	userEmailVerifyCmd.Flags().String("token", "", "Email verification token")
	userPasswordResetRequestCmd.Flags().String("email", "", "Account email")
	userPasswordResetConsumeCmd.Flags().String("token", "", "Password reset token")
	userPasswordResetConsumeCmd.Flags().String("password", "", "New password")
	userPhoneSetCmd.Flags().String("number", "", "Phone number in E.164")
	userPhoneVerifyCmd.Flags().String("otp", "", "OTP received by SMS")
	userLoginOtpSendCmd.Flags().String("method", "sms", "Delivery method: sms or email")
	userLoginOtpVerifyCmd.Flags().String("otp", "", "OTP code")
	userLoginOtpVerifyCmd.Flags().String("method", "", "Method type: totp, sms, email")
}
