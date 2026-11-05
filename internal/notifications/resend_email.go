package notifications

import (
	"fmt"

	"github.com/pilab-dev/shadow-sso/port"
	"github.com/resendlabs/resend-go"
)

// ResendEmailService implements domain.EmailService using Resend
type ResendEmailService struct {
	client    *resend.Client
	fromEmail string
	baseURL   string
	loader    port.TemplateLoader
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
// IsConfigured reports whether the service has the credentials needed to send mail.
func (s *ResendEmailService) IsConfigured() bool {
	return s != nil && s.client != nil && s.fromEmail != ""
}

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
		Html: func() string {
			if h, err := renderEmailTemplate("verification.html", emailTemplateData{Name: name, Link: verificationLink}, s.loader); err == nil {
				return h
			}
			return fmt.Sprintf(`<h1>Welcome %s!</h1><p>Verify your account:</p><a href="%s">Verify</a>`, name, verificationLink)
		}(),
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
		Html: func() string {
			if h, err := renderEmailTemplate("password_reset.html", emailTemplateData{Name: name, Link: resetLink}, s.loader); err == nil {
				return h
			}
			return fmt.Sprintf(`<h1>Hello %s</h1><p>Reset your password:</p><a href="%s">Reset Password</a>`, name, resetLink)
		}(),
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
		Html: func() string {
			if h, err := renderEmailTemplate("otp.html", emailTemplateData{OTP: otp}, s.loader); err == nil {
				return h
			}
			return fmt.Sprintf(`<p>Your one-time code is: <b>%s</b></p>`, otp)
		}(),
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
	subject = "Your MFA verification code"
	body, _ = renderEmailTemplate("mfa.html", emailTemplateData{Name: name, OTP: otp, Method: method}, s.loader)
	if body == "" {
		body = fmt.Sprintf(`<p>Hello %s, your %s code is: <b>%s</b></p>`, name, method, otp)
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
