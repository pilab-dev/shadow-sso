package domain

import (
	"errors" // Added for ErrUserNotFound
	"time"
)

// ErrUserNotFound is returned when a user is not found in the repository.
var ErrUserNotFound = errors.New("user not found")

// ErrConfigurationNotFound is returned when a configuration is not found.
var ErrConfigurationNotFound = errors.New("configuration not found")

// UserStatus defines the possible statuses of a user account.
type UserStatus string

const (
	UserStatusActive   UserStatus = "ACTIVE"
	UserStatusLocked   UserStatus = "LOCKED"
	UserStatusPending  UserStatus = "PENDING_ACTIVATION" // If email verification is implemented
)

// PushMFAChallenge represents an active push MFA challenge
type PushMFAChallenge struct {
	ChallengeID   string    `bson:"challenge_id" json:"challenge_id"`
	DeviceToken   string    `bson:"device_token" json:"device_token"`
	IPAddress     string    `bson:"ip_address" json:"ip_address"`
	UserAgent     string    `bson:"user_agent" json:"user_agent"`
	CreatedAt     time.Time `bson:"created_at" json:"created_at"`
	ExpiresAt     time.Time `bson:"expires_at" json:"expires_at"`
	Status        string    `bson:"status" json:"status"` // "pending", "approved", "denied", "expired"
}

// User represents a user in the system.
type User struct {
	ID                  string     `bson:"_id,omitempty" json:"id,omitempty"`
	Email               string     `bson:"email,unique" json:"email"`
	PasswordHash        string     `bson:"password_hash" json:"-"` // Usually not sent in JSON response
	Status              UserStatus `bson:"status" json:"status"`
	FirstName           string     `bson:"first_name,omitempty" json:"first_name,omitempty"`
	LastName            string     `bson:"last_name,omitempty" json:"last_name,omitempty"`
	Roles               []string   `bson:"roles,omitempty" json:"roles,omitempty"`
	CreatedAt           time.Time  `bson:"created_at" json:"created_at"`
	UpdatedAt           time.Time  `bson:"updated_at" json:"updated_at"`
	LastLoginAt         *time.Time `bson:"last_login_at,omitempty" json:"last_login_at,omitempty"`
	FailedLoginAttempts int        `bson:"failed_login_attempts,omitempty" json:"-"`

	// New 2FA fields
	IsTwoFactorEnabled    bool     `bson:"is_two_factor_enabled,omitempty" json:"is_two_factor_enabled,omitempty"`
	TwoFactorMethod       string   `bson:"two_factor_method,omitempty" json:"two_factor_method,omitempty"` // e.g., "TOTP", "HOTP", "EMAIL", "NONE"
	TwoFactorSecret       string   `bson:"two_factor_secret,omitempty" json:"-"`                            // Encrypted, never send via JSON
	TwoFactorRecoveryCodes []string `bson:"two_factor_recovery_codes,omitempty" json:"-"`                    // Hashed, never send via JSON

	// Email MFA fields
	EmailMFAEnabled       bool       `bson:"email_mfa_enabled,omitempty" json:"email_mfa_enabled,omitempty"`
	EmailMFAOTP           string     `bson:"email_mfa_otp,omitempty" json:"-"`                              // Never send via JSON
	EmailMFAOTPExpiresAt  *time.Time `bson:"email_mfa_otp_expires_at,omitempty" json:"-"`                   // Never send via JSON
	EmailMFAOTPCounter    uint64     `bson:"email_mfa_otp_counter,omitempty" json:"-"`                     // For HOTP-style email MFA
	EmailMFALastSentAt    *time.Time `bson:"email_mfa_last_sent_at,omitempty" json:"-"`                     // Track rate limiting

	// Push MFA fields
	PushMFAEnabled        bool       `bson:"push_mfa_enabled,omitempty" json:"push_mfa_enabled,omitempty"`
	PushMFADeviceTokens   []string   `bson:"push_mfa_device_tokens,omitempty" json:"-"`                     // Firebase device tokens, never send via JSON
	PushMFAChallenges     []PushMFAChallenge `bson:"push_mfa_challenges,omitempty" json:"-"`                // Active push challenges, never send via JSON

	// Phone verification fields
	PhoneNumber                     string     `bson:"phone_number,omitempty" json:"phone_number,omitempty"`
	IsPhoneNumberVerified           bool       `bson:"is_phone_number_verified,omitempty" json:"is_phone_number_verified,omitempty"`
	PhoneVerificationOtp            string     `bson:"phone_verification_otp,omitempty" json:"-"` // Never send via JSON
	PhoneVerificationOtpExpiresAt   *time.Time `bson:"phone_verification_otp_expires_at,omitempty" json:"-"` // Never send via JSON
	PhoneVerificationAttempts       int        `bson:"phone_verification_attempts,omitempty" json:"-"` // Track failed attempts
	PhoneVerificationLastAttemptAt  *time.Time `bson:"phone_verification_last_attempt_at,omitempty" json:"-"` // Track last attempt time
}
