package domain

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/pilab-dev/shadow-sso/internal/auth/totp"
)

var (
	ErrEmailMFAAlreadyEnabled = errors.New("email MFA is already enabled")
	ErrEmailMFANotEnabled     = errors.New("email MFA is not enabled")
	ErrInvalidEmailOTP        = errors.New("invalid email OTP")
	ErrEmailOTPExpired        = errors.New("email OTP has expired")
	ErrEmailOTPNotFound       = errors.New("no email OTP found")
	ErrRateLimitExceeded      = errors.New("rate limit exceeded, please wait before requesting another OTP")
)

// MFAService handles Multi-Factor Authentication business logic
type MFAService struct {
	userRepo       UserRepository
	emailService   EmailService
	pushMFAService *PushMFAService
	// Configuration
	maxOTPRequestsPerHour int
	maxOTPAttemptsPerHour int
	otpRequestWindow      time.Duration
	otpAttemptWindow      time.Duration
	otpExpiryDuration     time.Duration
}

// MFAConfig holds configuration for MFA
type MFAConfig struct {
	MaxOTPRequestsPerHour int
	MaxOTPAttemptsPerHour int
	OTPRequestWindow      time.Duration
	OTPAttemptWindow      time.Duration
	OTPExpiryDuration     time.Duration
}

// NewMFAService creates a new MFA service
func NewMFAService(userRepo UserRepository, emailService EmailService, pushMFAService *PushMFAService) *MFAService {
	return &MFAService{
		userRepo:              userRepo,
		emailService:          emailService,
		pushMFAService:        pushMFAService,
		maxOTPRequestsPerHour: 5,  // Default: 5 OTP requests per hour
		maxOTPAttemptsPerHour: 10, // Default: 10 verification attempts per hour
		otpRequestWindow:      time.Hour,
		otpAttemptWindow:      time.Hour,
		otpExpiryDuration:     5 * time.Minute, // 5 minutes expiry
	}
}

// NewMFAServiceWithConfig creates a new MFA service with custom config
func NewMFAServiceWithConfig(userRepo UserRepository, emailService EmailService, config MFAConfig) *MFAService {
	return &MFAService{
		userRepo:              userRepo,
		emailService:          emailService,
		maxOTPRequestsPerHour: config.MaxOTPRequestsPerHour,
		maxOTPAttemptsPerHour: config.MaxOTPAttemptsPerHour,
		otpRequestWindow:      config.OTPRequestWindow,
		otpAttemptWindow:      config.OTPAttemptWindow,
		otpExpiryDuration:     config.OTPExpiryDuration,
	}
}

// InitiateEmailMFASetup sends an OTP to the user's email for MFA setup
func (s *MFAService) InitiateEmailMFASetup(ctx context.Context, userID string) error {
	user, err := s.userRepo.GetUserByID(ctx, userID)
	if err != nil {
		return fmt.Errorf("failed to get user: %w", err)
	}

	if user.EmailMFAEnabled {
		return ErrEmailMFAAlreadyEnabled
	}

	// Check rate limiting
	if user.EmailMFALastSentAt != nil {
		timeSinceLastSend := time.Since(*user.EmailMFALastSentAt)
		if timeSinceLastSend < s.otpRequestWindow {
			// Basic rate limiting - could be enhanced with counters
			minRequestInterval := time.Minute
			if timeSinceLastSend < minRequestInterval {
				return ErrRateLimitExceeded
			}
		}
	}

	// Generate 6-digit OTP
	otp, err := s.generateOTP()
	if err != nil {
		return fmt.Errorf("failed to generate OTP: %w", err)
	}

	// Store OTP with expiration
	expiresAt := time.Now().Add(s.otpExpiryDuration)
	err = s.userRepo.StoreEmailMFAOtp(ctx, userID, otp, expiresAt)
	if err != nil {
		return fmt.Errorf("failed to store email MFA OTP: %w", err)
	}

	// Send OTP via email
	err = s.emailService.SendMFAEmail(user.Email, user.FirstName+" "+user.LastName, otp, "EMAIL")
	if err != nil {
		// Clear stored OTP if sending failed
		_ = s.userRepo.ClearEmailMFAOtp(ctx, userID)
		return fmt.Errorf("failed to send MFA email: %w", err)
	}

	return nil
}

// VerifyAndEnableEmailMFA verifies the OTP and enables email MFA
func (s *MFAService) VerifyAndEnableEmailMFA(ctx context.Context, userID, otp string) error {
	user, err := s.userRepo.GetUserByID(ctx, userID)
	if err != nil {
		return fmt.Errorf("failed to get user: %w", err)
	}

	if user.EmailMFAEnabled {
		return ErrEmailMFAAlreadyEnabled
	}

	// Check if OTP exists and hasn't expired
	if user.EmailMFAOTP == "" {
		return ErrEmailOTPNotFound
	}

	if user.EmailMFAOTPExpiresAt == nil || time.Now().After(*user.EmailMFAOTPExpiresAt) {
		_ = s.userRepo.ClearEmailMFAOtp(ctx, userID)
		return ErrEmailOTPExpired
	}

	// Verify OTP
	if user.EmailMFAOTP != otp {
		return ErrInvalidEmailOTP
	}

	// Generate recovery codes
	_, hashedCodes, err := totp.GenerateRecoveryCodes(totp.DefaultNumRecoveryCodes, totp.DefaultRecoveryCodeLength)
	if err != nil {
		return fmt.Errorf("failed to generate recovery codes: %w", err)
	}

	// Enable email MFA and store recovery codes
	err = s.userRepo.EnableEmailMFA(ctx, userID)
	if err != nil {
		return fmt.Errorf("failed to enable email MFA: %w", err)
	}

	// Update user with recovery codes (this would need to be added to UserRepository interface)
	user.IsTwoFactorEnabled = true
	user.TwoFactorMethod = "EMAIL"
	user.TwoFactorRecoveryCodes = hashedCodes

	err = s.userRepo.UpdateUser(ctx, user)
	if err != nil {
		return fmt.Errorf("failed to update user with recovery codes: %w", err)
	}

	// Clear the temporary OTP
	err = s.userRepo.ClearEmailMFAOtp(ctx, userID)
	if err != nil {
		// Log error but don't fail the operation
		fmt.Printf("Warning: failed to clear email MFA OTP: %v\n", err)
	}

	return nil
}

// SendMFAChallenge sends an MFA challenge based on the user's configured method
func (s *MFAService) SendMFAChallenge(ctx context.Context, userID string) (method string, counter uint64, challengeID string, err error) {
	user, err := s.userRepo.GetUserByID(ctx, userID)
	if err != nil {
		return "", 0, "", fmt.Errorf("failed to get user: %w", err)
	}

	if !user.IsTwoFactorEnabled {
		return "", 0, "", errors.New("2FA is not enabled for this user")
	}

	switch user.TwoFactorMethod {
	case "EMAIL":
		method, counter, err = s.sendEmailMFAChallenge(ctx, user)
		return method, counter, "", err
	case "TOTP":
		return "TOTP", 0, "", errors.New("TOTP challenges are handled by authenticator apps")
	case "HOTP":
		method, counter, err = s.sendHOTPChallenge(ctx, user)
		return method, counter, "", err
	case "PUSH":
		return s.sendPushMFAChallenge(ctx, user)
	default:
		return "", 0, "", errors.New("unsupported MFA method")
	}
}

// sendEmailMFAChallenge sends an email OTP for MFA challenge
func (s *MFAService) sendEmailMFAChallenge(ctx context.Context, user *User) (string, uint64, error) {
	if !user.EmailMFAEnabled {
		return "", 0, ErrEmailMFANotEnabled
	}

	// Check rate limiting
	if user.EmailMFALastSentAt != nil {
		timeSinceLastSend := time.Since(*user.EmailMFALastSentAt)
		if timeSinceLastSend < s.otpRequestWindow {
			minRequestInterval := time.Minute
			if timeSinceLastSend < minRequestInterval {
				return "", 0, ErrRateLimitExceeded
			}
		}
	}

	// Generate 6-digit OTP
	otp, err := s.generateOTP()
	if err != nil {
		return "", 0, fmt.Errorf("failed to generate OTP: %w", err)
	}

	// Store OTP with expiration
	expiresAt := time.Now().Add(s.otpExpiryDuration)
	err = s.userRepo.StoreEmailMFAOtp(ctx, user.ID, otp, expiresAt)
	if err != nil {
		return "", 0, fmt.Errorf("failed to store email MFA OTP: %w", err)
	}

	// Send OTP via email
	err = s.emailService.SendMFAEmail(user.Email, user.FirstName+" "+user.LastName, otp, "EMAIL")
	if err != nil {
		_ = s.userRepo.ClearEmailMFAOtp(ctx, user.ID)
		return "", 0, fmt.Errorf("failed to send MFA email: %w", err)
	}

	return "EMAIL", 0, nil
}

// sendHOTPChallenge would handle HOTP challenges (placeholder for future implementation)
func (s *MFAService) sendHOTPChallenge(ctx context.Context, user *User) (string, uint64, error) {
	// For HOTP, the challenge would typically be handled by the authenticator app
	// This is a placeholder for future implementation
	return "HOTP", user.EmailMFAOTPCounter, nil
}

// sendPushMFAChallenge sends a push MFA challenge
func (s *MFAService) sendPushMFAChallenge(ctx context.Context, user *User) (string, uint64, string, error) {
	if s.pushMFAService == nil {
		return "", 0, "", errors.New("push MFA service not configured")
	}

	// Get IP address and user agent from context (would need to be passed in)
	// For now, use placeholder values
	ipAddress := "unknown"
	userAgent := "unknown"

	challengeID, err := s.pushMFAService.CreatePushMFAChallenge(ctx, user, ipAddress, userAgent)
	if err != nil {
		return "", 0, "", err
	}

	return "PUSH", 0, challengeID, nil
}

// verifyPushMFAChallenge verifies a push MFA challenge
func (s *MFAService) verifyPushMFAChallenge(ctx context.Context, user *User, challengeID string, approved bool) (bool, error) {
	if s.pushMFAService == nil {
		return false, errors.New("push MFA service not configured")
	}

	err := s.pushMFAService.VerifyPushMFAChallenge(ctx, user.ID, challengeID, approved)
	if err != nil {
		return false, err
	}

	return approved, nil
}

// VerifyMFAChallenge verifies an MFA code based on the user's configured method
func (s *MFAService) VerifyMFAChallenge(ctx context.Context, userID, code string, counter uint64) (bool, error) {
	return s.VerifyMFAChallengeWithChallengeID(ctx, userID, "", code, counter)
}

// VerifyMFAChallengeWithChallengeID verifies an MFA challenge, supporting push MFA
func (s *MFAService) VerifyMFAChallengeWithChallengeID(ctx context.Context, userID, challengeID, code string, counter uint64) (bool, error) {
	user, err := s.userRepo.GetUserByID(ctx, userID)
	if err != nil {
		return false, fmt.Errorf("failed to get user: %w", err)
	}

	if !user.IsTwoFactorEnabled {
		return false, errors.New("2FA is not enabled for this user")
	}

	switch user.TwoFactorMethod {
	case "EMAIL":
		return s.verifyEmailMFAChallenge(ctx, user, code)
	case "TOTP":
		valid, err := totp.ValidateTOTPCode(user.TwoFactorSecret, code)
		return valid, err
	case "HOTP":
		valid, err := totp.ValidateHOTPCode(user.TwoFactorSecret, code, counter)
		if err != nil {
			return false, err
		}
		if valid {
			// Update counter on successful validation
			err = s.userRepo.UpdateEmailMFACounter(ctx, userID, counter+1)
			if err != nil {
				return false, fmt.Errorf("failed to update HOTP counter: %w", err)
			}
		}
		return valid, nil
	case "PUSH":
		// For push MFA, we expect approval/deny responses, not codes
		// This method is for backward compatibility
		if code == "approve" || code == "approved" {
			return s.verifyPushMFAChallenge(ctx, user, challengeID, true)
		} else if code == "deny" || code == "denied" {
			return s.verifyPushMFAChallenge(ctx, user, challengeID, false)
		}
		return false, errors.New("invalid push MFA response")
	default:
		return false, errors.New("unsupported MFA method")
	}
}

// verifyEmailMFAChallenge verifies an email OTP for MFA challenge
func (s *MFAService) verifyEmailMFAChallenge(ctx context.Context, user *User, code string) (bool, error) {
	if !user.EmailMFAEnabled {
		return false, ErrEmailMFANotEnabled
	}

	// Check if OTP exists and hasn't expired
	if user.EmailMFAOTP == "" {
		return false, nil
	}

	if user.EmailMFAOTPExpiresAt == nil || time.Now().After(*user.EmailMFAOTPExpiresAt) {
		_ = s.userRepo.ClearEmailMFAOtp(ctx, user.ID)
		return false, nil
	}

	// Verify OTP
	if user.EmailMFAOTP != code {
		return false, nil
	}

	// Clear the OTP after successful verification
	err := s.userRepo.ClearEmailMFAOtp(ctx, user.ID)
	if err != nil {
		// Log error but don't fail verification
		fmt.Printf("Warning: failed to clear email MFA OTP after verification: %v\n", err)
	}

	return true, nil
}

// DisableEmailMFA disables email MFA for a user
func (s *MFAService) DisableEmailMFA(ctx context.Context, userID string) error {
	user, err := s.userRepo.GetUserByID(ctx, userID)
	if err != nil {
		return fmt.Errorf("failed to get user: %w", err)
	}

	if !user.EmailMFAEnabled {
		return ErrEmailMFANotEnabled
	}

	err = s.userRepo.DisableEmailMFA(ctx, userID)
	if err != nil {
		return fmt.Errorf("failed to disable email MFA: %w", err)
	}

	// Update user's 2FA status
	user.IsTwoFactorEnabled = false
	user.TwoFactorMethod = "NONE"
	user.TwoFactorSecret = ""
	user.TwoFactorRecoveryCodes = nil

	err = s.userRepo.UpdateUser(ctx, user)
	if err != nil {
		return fmt.Errorf("failed to update user 2FA status: %w", err)
	}

	return nil
}

// generateOTP generates a random 6-digit OTP
func (s *MFAService) generateOTP() (string, error) {
	// Generate a random number between 100000 and 999999
	min := int64(100000)
	max := int64(999999)

	num, err := rand.Int(rand.Reader, big.NewInt(max-min+1))
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("%06d", min+num.Int64()), nil
}
