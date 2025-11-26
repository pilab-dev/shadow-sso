package domain

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"time"
)

// Phone verification errors
var (
	ErrUserHasNoPhoneNumber = errors.New("user has no phone number")
	ErrNoOTPFound           = errors.New("no OTP found, please request a new one")
	ErrOTPExpired           = errors.New("OTP has expired, please request a new one")
	ErrInvalidOTP           = errors.New("invalid OTP")
)

// PhoneVerificationService handles phone verification business logic
type PhoneVerificationService struct {
	userRepo              UserRepository
	smsService            SMSService
	maxOTPRequestsPerHour int
	maxOTPAttemptsPerHour int
	otpRequestWindow      time.Duration
	otpAttemptWindow      time.Duration
}

// PhoneVerificationConfig holds configuration for phone verification
type PhoneVerificationConfig struct {
	MaxOTPRequestsPerHour int
	MaxOTPAttemptsPerHour int
	OTPRequestWindow      time.Duration
	OTPAttemptWindow      time.Duration
}

// NewPhoneVerificationService creates a new phone verification service
func NewPhoneVerificationService(userRepo UserRepository, smsService SMSService) *PhoneVerificationService {
	return &PhoneVerificationService{
		userRepo:              userRepo,
		smsService:            smsService,
		maxOTPRequestsPerHour: 5,  // Default: 5 OTP requests per hour
		maxOTPAttemptsPerHour: 10, // Default: 10 verification attempts per hour
		otpRequestWindow:      time.Hour,
		otpAttemptWindow:      time.Hour,
	}
}

// NewPhoneVerificationServiceWithConfig creates a new phone verification service with custom config
func NewPhoneVerificationServiceWithConfig(userRepo UserRepository, smsService SMSService, config PhoneVerificationConfig) *PhoneVerificationService {
	return &PhoneVerificationService{
		userRepo:              userRepo,
		smsService:            smsService,
		maxOTPRequestsPerHour: config.MaxOTPRequestsPerHour,
		maxOTPAttemptsPerHour: config.MaxOTPAttemptsPerHour,
		otpRequestWindow:      config.OTPRequestWindow,
		otpAttemptWindow:      config.OTPAttemptWindow,
	}
}

// SendVerificationOTP sends a verification OTP to the user's phone number
func (s *PhoneVerificationService) SendVerificationOTP(ctx context.Context, userID string) error {
	// Get user
	user, err := s.userRepo.GetUserByID(ctx, userID)
	if err != nil {
		return fmt.Errorf("failed to get user: %w", err)
	}

	if user.PhoneNumber == "" {
		return ErrUserHasNoPhoneNumber
	}

	if user.IsPhoneNumberVerified {
		return errors.New("phone number is already verified")
	}

	// Basic rate limiting: check if user has requested OTP too recently
	// In a production system, this would be enhanced with proper rate limiting storage
	if user.PhoneVerificationOtpExpiresAt != nil {
		// If there's a recent OTP (within last 2 minutes), don't allow new request
		minRequestInterval := 2 * time.Minute
		if time.Since(*user.PhoneVerificationOtpExpiresAt) < -minRequestInterval {
			return errors.New("please wait before requesting a new OTP")
		}
	}

	// Generate OTP (6-digit)
	otp := fmt.Sprintf("%06d", s.generateOTP())

	// Store OTP with expiration (10 minutes)
	expiresAt := time.Now().Add(10 * time.Minute)
	err = s.userRepo.StorePhoneVerificationOtp(ctx, userID, otp, expiresAt)
	if err != nil {
		return fmt.Errorf("failed to store OTP: %w", err)
	}

	// Send OTP via SMS
	err = s.smsService.SendOTP(user.PhoneNumber, otp)
	if err != nil {
		// Clear stored OTP if sending failed
		_ = s.userRepo.ClearPhoneVerificationOtp(ctx, userID)
		return fmt.Errorf("failed to send SMS: %w", err)
	}

	return nil
}

// VerifyPhoneNumber verifies the user's phone number using the provided OTP
func (s *PhoneVerificationService) VerifyPhoneNumber(ctx context.Context, userID, otp string) error {
	// Get user
	user, err := s.userRepo.GetUserByID(ctx, userID)
	if err != nil {
		return fmt.Errorf("failed to get user: %w", err)
	}

	if user.PhoneNumber == "" {
		return ErrUserHasNoPhoneNumber
	}

	if user.IsPhoneNumberVerified {
		return nil // Already verified, consider this success
	}

	// Basic rate limiting for verification attempts
	if user.PhoneVerificationLastAttemptAt != nil {
		timeSinceLastAttempt := time.Since(*user.PhoneVerificationLastAttemptAt)
		if timeSinceLastAttempt < s.otpAttemptWindow && user.PhoneVerificationAttempts >= s.maxOTPAttemptsPerHour {
			return errors.New("too many verification attempts, please try again later")
		}

		// Reset counter if window has passed
		if timeSinceLastAttempt >= s.otpAttemptWindow {
			user.PhoneVerificationAttempts = 0
		}
	}

	// Update attempt tracking
	now := time.Now()
	user.PhoneVerificationLastAttemptAt = &now
	user.PhoneVerificationAttempts++

	// Check if OTP exists and hasn't expired
	if user.PhoneVerificationOtp == "" {
		err = s.userRepo.UpdateUser(ctx, user)
		if err != nil {
			return fmt.Errorf("failed to update user attempt tracking: %w", err)
		}
		return ErrNoOTPFound
	}

	if user.PhoneVerificationOtpExpiresAt == nil || time.Now().After(*user.PhoneVerificationOtpExpiresAt) {
		_ = s.userRepo.ClearPhoneVerificationOtp(ctx, userID)
		err = s.userRepo.UpdateUser(ctx, user)
		if err != nil {
			return fmt.Errorf("failed to update user attempt tracking: %w", err)
		}
		return ErrOTPExpired
	}

	// Verify OTP
	if user.PhoneVerificationOtp != otp {
		err = s.userRepo.UpdateUser(ctx, user)
		if err != nil {
			return fmt.Errorf("failed to update user attempt tracking: %w", err)
		}
		return ErrInvalidOTP
	}

	// Mark phone number as verified (this will also clear the OTP and reset attempts)
	user.IsPhoneNumberVerified = true
	user.PhoneVerificationOtp = ""
	user.PhoneVerificationOtpExpiresAt = nil
	user.PhoneVerificationAttempts = 0
	user.PhoneVerificationLastAttemptAt = nil

	err = s.userRepo.UpdateUser(ctx, user)
	if err != nil {
		return fmt.Errorf("failed to update user verification status: %w", err)
	}

	return nil
}

// generateOTP generates a random 6-digit OTP
func (s *PhoneVerificationService) generateOTP() int {
	return 100000 + rand.Intn(900000) // Generates number between 100000-999999
}
