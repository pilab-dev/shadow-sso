package notifications

import (
	"fmt"

	"github.com/resendlabs/resend-go"
)

// ResendEmailService implements domain.EmailService using Resend
type ResendEmailService struct {
	client    *resend.Client
	fromEmail string
	baseURL   string
}

// NewResendEmailService creates a new Resend email service
func NewResendEmailService(apiKey, fromEmail, baseURL string) *ResendEmailService {
	if apiKey == "" {
		// Return service with nil client - will fail gracefully when used
		return &ResendEmailService{
			fromEmail: fromEmail,
			baseURL:   baseURL,
		}
	}

	client := resend.NewClient(apiKey)

	return &ResendEmailService{
		client:    client,
		fromEmail: fromEmail,
		baseURL:   baseURL,
	}
}

// SendVerificationEmail sends a verification email
func (s *ResendEmailService) SendVerificationEmail(to, name, verificationLink string) error {
	if s.client == nil {
		return fmt.Errorf("Resend service not properly configured")
	}

	if s.fromEmail == "" {
		return fmt.Errorf("from email not configured")
	}

	params := &resend.SendEmailRequest{
		From:    s.fromEmail,
		To:      []string{to},
		Subject: "Verify Your Account",
		Html: fmt.Sprintf(`
			<!DOCTYPE html>
			<html>
			<head>
				<meta charset="utf-8">
				<title>Verify Your Account</title>
			</head>
			<body>
				<h1>Welcome %s!</h1>
				<p>Please click the link below to verify your account:</p>
				<a href="%s" style="background-color: #007bff; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">Verify Account</a>
				<p>If you didn't create an account, please ignore this email.</p>
				<p>This link will expire in 24 hours.</p>
			</body>
			</html>
		`, name, verificationLink),
	}

	_, err := s.client.Emails.Send(params)
	if err != nil {
		return fmt.Errorf("failed to send verification email via Resend: %w", err)
	}

	return nil
}

// SendPasswordResetEmail sends a password reset email
func (s *ResendEmailService) SendPasswordResetEmail(to, name, resetLink string) error {
	if s.client == nil {
		return fmt.Errorf("Resend service not properly configured")
	}

	if s.fromEmail == "" {
		return fmt.Errorf("from email not configured")
	}

	params := &resend.SendEmailRequest{
		From:    s.fromEmail,
		To:      []string{to},
		Subject: "Reset Your Password",
		Html: fmt.Sprintf(`
			<!DOCTYPE html>
			<html>
			<head>
				<meta charset="utf-8">
				<title>Reset Your Password</title>
			</head>
			<body>
				<h1>Hello %s</h1>
				<p>You have requested to reset your password. Click the link below to proceed:</p>
				<a href="%s" style="background-color: #dc3545; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">Reset Password</a>
				<p>If you didn't request a password reset, please ignore this email.</p>
				<p>This link will expire in 1 hour.</p>
			</body>
			</html>
		`, name, resetLink),
	}

	_, err := s.client.Emails.Send(params)
	if err != nil {
		return fmt.Errorf("failed to send password reset email via Resend: %w", err)
	}

	return nil
}

// SendOTPEmail sends an OTP via email
func (s *ResendEmailService) SendOTPEmail(to, otp string) error {
	if s.client == nil {
		return fmt.Errorf("Resend service not properly configured")
	}

	if s.fromEmail == "" {
		return fmt.Errorf("from email not configured")
	}

	params := &resend.SendEmailRequest{
		From:    s.fromEmail,
		To:      []string{to},
		Subject: "Your Verification Code",
		Html: fmt.Sprintf(`
			<!DOCTYPE html>
			<html>
			<head>
				<meta charset="utf-8">
				<title>Your Verification Code</title>
			</head>
			<body>
				<h1>Your Verification Code</h1>
				<p>Your verification code is:</p>
				<h2 style="font-family: monospace; font-size: 32px; color: #007bff;">%s</h2>
				<p>This code will expire in 10 minutes.</p>
				<p>If you didn't request this code, please ignore this email.</p>
			</body>
			</html>
		`, otp),
	}

	_, err := s.client.Emails.Send(params)
	if err != nil {
		return fmt.Errorf("failed to send OTP email via Resend: %w", err)
	}

	return nil
}

// SendMFAEmail sends an MFA code via email for two-factor authentication
func (s *ResendEmailService) SendMFAEmail(to, name, otp, method string) error {
	if s.client == nil {
		return fmt.Errorf("Resend service not properly configured")
	}

	if s.fromEmail == "" {
		return fmt.Errorf("from email not configured")
	}

	var subject, body string
	switch method {
	case "TOTP", "HOTP":
		subject = "Your Multi-Factor Authentication Code"
		body = fmt.Sprintf(`
			<!DOCTYPE html>
			<html>
			<head>
				<meta charset="utf-8">
				<title>Your MFA Code</title>
			</head>
			<body>
				<h1>Hello %s</h1>
				<p>Your multi-factor authentication code is:</p>
				<h2 style="font-family: monospace; font-size: 32px; color: #007bff;">%s</h2>
				<p>This code will expire in 5 minutes.</p>
				<p>If you didn't request this code, please contact support immediately.</p>
			</body>
			</html>
		`, name, otp)
	case "EMAIL":
		subject = "Your Email Verification Code"
		body = fmt.Sprintf(`
			<!DOCTYPE html>
			<html>
			<head>
				<meta charset="utf-8">
				<title>Your Email Verification Code</title>
			</head>
			<body>
				<h1>Hello %s</h1>
				<p>Your email verification code is:</p>
				<h2 style="font-family: monospace; font-size: 32px; color: #dc3545;">%s</h2>
				<p>This code will expire in 5 minutes.</p>
				<p>If you didn't request this code, please ignore this email.</p>
			</body>
			</html>
		`, name, otp)
	default:
		subject = "Your Security Code"
		body = fmt.Sprintf(`
			<!DOCTYPE html>
			<html>
			<head>
				<meta charset="utf-8">
				<title>Your Security Code</title>
			</head>
			<body>
				<h1>Hello %s</h1>
				<p>Your security code is:</p>
				<h2 style="font-family: monospace; font-size: 32px; color: #28a745;">%s</h2>
				<p>This code will expire in 5 minutes.</p>
				<p>If you didn't request this code, please contact support immediately.</p>
			</body>
			</html>
		`, name, otp)
	}

	params := &resend.SendEmailRequest{
		From:    s.fromEmail,
		To:      []string{to},
		Subject: subject,
		Html:    body,
	}

	_, err := s.client.Emails.Send(params)
	if err != nil {
		return fmt.Errorf("failed to send MFA email via Resend: %w", err)
	}

	return nil
}
