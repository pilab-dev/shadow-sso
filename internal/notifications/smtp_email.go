package notifications

import (
	"fmt"
	"net/smtp"
	"strings"

	"github.com/pilab-dev/shadow-sso/domain"
)

// SMTPEmailService implements domain.EmailService over SMTP. It can target
// PiMail (or any SMTP server) by configuring host/port/credentials, and
// renders HTML bodies for each message type.
type SMTPEmailService struct {
	host     string
	port     string
	username string
	password string
	from     string
	baseURL  string
}

func NewSMTPEmailService(host, port, username, password, from, baseURL string) *SMTPEmailService {
	return &SMTPEmailService{host: host, port: port, username: username, password: password, from: from, baseURL: baseURL}
}

func (s *SMTPEmailService) IsConfigured() bool {
	return s != nil && s.host != "" && s.from != ""
}

func (s *SMTPEmailService) send(to, subject, html string) error {
	if !s.IsConfigured() {
		return fmt.Errorf("smtp service not configured")
	}
	addr := s.host + ":" + s.port
	auth := smtp.PlainAuth("", s.username, s.password, s.host)
	headers := []string{
		"From: " + s.from,
		"To: " + to,
		"Subject: " + subject,
		"MIME-Version: 1.0",
		"Content-Type: text/html; charset=UTF-8",
	}
	msg := strings.Join(headers, "\r\n") + "\r\n\r\n" + html
	return smtp.SendMail(addr, auth, s.from, []string{to}, []byte(msg))
}

func (s *SMTPEmailService) SendVerificationEmail(to, name, verificationLink string) error {
	html := fmt.Sprintf(`<h1>Welcome %s!</h1><p>Verify your account:</p><a href="%s">Verify</a>`, name, verificationLink)
	return s.send(to, "Verify Your Account", html)
}

func (s *SMTPEmailService) SendPasswordResetEmail(to, name, resetLink string) error {
	html := fmt.Sprintf(`<h1>Hello %s</h1><p>Reset your password:</p><a href="%s">Reset Password</a>`, name, resetLink)
	return s.send(to, "Reset Your Password", html)
}

func (s *SMTPEmailService) SendOTPEmail(to, otp string) error {
	html := fmt.Sprintf(`<p>Your one-time code is: <b>%s</b></p>`, otp)
	return s.send(to, "Your verification code", html)
}

func (s *SMTPEmailService) SendMFAEmail(to, name, otp, method string) error {
	html := fmt.Sprintf(`<p>Hello %s, your %s code is: <b>%s</b></p>`, name, method, otp)
	return s.send(to, "MFA verification code", html)
}

var _ domain.EmailService = (*SMTPEmailService)(nil)