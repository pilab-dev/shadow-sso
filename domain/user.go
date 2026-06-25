package domain

import (
	"errors"
	"time"
)

// ErrUserNotFound is returned when a user is not found in the repository.
var ErrUserNotFound = errors.New("user not found")

// ErrConfigurationNotFound is returned when a configuration is not found.
var ErrConfigurationNotFound = errors.New("configuration not found")

// UserStatus defines the possible statuses of a user account.
type UserStatus string

const (
	UserStatusActive  UserStatus = "ACTIVE"
	UserStatusLocked  UserStatus = "LOCKED"
	UserStatusPending UserStatus = "PENDING_ACTIVATION"
)

// MfaMethodType defines the type of MFA method.
type MfaMethodType string

const (
	MfaMethodTypeTOTP     MfaMethodType = "TOTP"
	MfaMethodTypeSMS      MfaMethodType = "SMS"
	MfaMethodTypeEmail    MfaMethodType = "EMAIL"
	MfaMethodTypeWebAuthn MfaMethodType = "WEBAUTHN"
	MfaMethodTypePush     MfaMethodType = "PUSH"
	MfaMethodTypeNone     MfaMethodType = "NONE"
)

// MfaMethod represents an MFA method for a user.
type MfaMethod struct {
	ID        string        `bson:"id" json:"id"`
	Type      MfaMethodType `bson:"type" json:"type"`
	Secret    string        `bson:"secret,omitempty" json:"-"`
	Verified  bool          `bson:"verified" json:"verified"`
	CreatedAt time.Time     `bson:"created_at" json:"created_at"`
	Name      string        `bson:"name,omitempty" json:"name"`
}

// WebAuthnDevice represents a registered WebAuthn device.
type WebAuthnDevice struct {
	ID           string    `bson:"id" json:"id"`
	Name         string    `bson:"name" json:"name"`
	CredentialID string    `bson:"credential_id" json:"credential_id"`
	PublicKey    string    `bson:"public_key" json:"public_key"`
	Counter      int32     `bson:"counter" json:"counter"`
	CreatedAt    time.Time `bson:"created_at" json:"created_at"`
	Transports   []string  `bson:"transports,omitempty" json:"transports"`
}

// PushMFAChallenge represents an active push MFA challenge
type PushMFAChallenge struct {
	ChallengeID string    `bson:"challenge_id" json:"challenge_id"`
	DeviceToken string    `bson:"device_token" json:"device_token"`
	IPAddress   string    `bson:"ip_address" json:"ip_address"`
	UserAgent   string    `bson:"user_agent" json:"user_agent"`
	CreatedAt   time.Time `bson:"created_at" json:"created_at"`
	ExpiresAt   time.Time `bson:"expires_at" json:"expires_at"`
	Status      string    `bson:"status" json:"status"`
}

// User represents a user in the system.
type User struct {
	ID                  string     `bson:"_id,omitempty" json:"id,omitempty"`
	Email               string     `bson:"email,unique" json:"email"`
	PasswordHash        string     `bson:"password_hash" json:"-"`
	Status              UserStatus `bson:"status" json:"status"`
	FirstName           string     `bson:"first_name,omitempty" json:"first_name,omitempty"`
	LastName            string     `bson:"last_name,omitempty" json:"last_name,omitempty"`
	Roles               []string   `bson:"roles,omitempty" json:"roles,omitempty"`
	CreatedAt           time.Time  `bson:"created_at" json:"created_at"`
	UpdatedAt           time.Time  `bson:"updated_at" json:"updated_at"`
	LastLoginAt         *time.Time `bson:"last_login_at,omitempty" json:"last_login_at,omitempty"`
	FailedLoginAttempts int        `bson:"failed_login_attempts,omitempty" json:"failed_login_attempts,omitempty"`
	LastFailedLoginTime *time.Time `bson:"last_failed_login_time,omitempty" json:"-"`

	// MFA Methods (multiple methods supported)
	MfaMethods []MfaMethod `bson:"mfa_methods,omitempty" json:"mfa_methods,omitempty"`

	// WebAuthn Devices
	WebAuthnDevices []WebAuthnDevice `bson:"webauthn_devices,omitempty" json:"webauthn_devices,omitempty"`

	// Legacy 2FA fields (for backward compatibility)
	IsTwoFactorEnabled     bool     `bson:"is_two_factor_enabled,omitempty" json:"is_two_factor_enabled,omitempty"`
	TwoFactorMethod        string   `bson:"two_factor_method,omitempty" json:"two_factor_method,omitempty"`
	TwoFactorSecret        string   `bson:"two_factor_secret,omitempty" json:"-"`
	TwoFactorRecoveryCodes []string `bson:"two_factor_recovery_codes,omitempty" json:"-"`

	// Email MFA fields
	EmailMFAEnabled      bool       `bson:"email_mfa_enabled,omitempty" json:"email_mfa_enabled,omitempty"`
	EmailMFAOTP          string     `bson:"email_mfa_otp,omitempty" json:"-"`
	EmailMFAOTPExpiresAt *time.Time `bson:"email_mfa_otp_expires_at,omitempty" json:"-"`
	EmailMFAOTPCounter   uint64     `bson:"email_mfa_otp_counter,omitempty" json:"-"`
	EmailMFALastSentAt   *time.Time `bson:"email_mfa_last_sent_at,omitempty" json:"-"`

	// Push MFA fields
	PushMFAEnabled      bool               `bson:"push_mfa_enabled,omitempty" json:"push_mfa_enabled,omitempty"`
	PushMFADeviceTokens []string           `bson:"push_mfa_device_tokens,omitempty" json:"-"`
	PushMFAChallenges   []PushMFAChallenge `bson:"push_mfa_challenges,omitempty" json:"-"`

	// Phone verification fields
	PhoneNumber                    string     `bson:"phone_number,omitempty" json:"phone_number,omitempty"`
	IsPhoneNumberVerified          bool       `bson:"is_phone_number_verified,omitempty" json:"is_phone_number_verified,omitempty"`
	PhoneVerificationOtp           string     `bson:"phone_verification_otp,omitempty" json:"-"`
	PhoneVerificationOtpExpiresAt  *time.Time `bson:"phone_verification_otp_expires_at,omitempty" json:"-"`
	PhoneVerificationAttempts      int        `bson:"phone_verification_attempts,omitempty" json:"-"`
	PhoneVerificationLastAttemptAt *time.Time `bson:"phone_verification_last_attempt_at,omitempty" json:"-"`

	// Email verification fields
	IsEmailVerified                 bool       `bson:"is_email_verified,omitempty" json:"is_email_verified,omitempty"`
	EmailVerificationToken          string     `bson:"email_verification_token,omitempty" json:"-"`
	EmailVerificationTokenExpiresAt *time.Time `bson:"email_verification_token_expires_at,omitempty" json:"-"`

	// Password reset fields
	PasswordResetToken          string     `bson:"password_reset_token,omitempty" json:"-"`
	PasswordResetTokenExpiresAt *time.Time `bson:"password_reset_token_expires_at,omitempty" json:"-"`

	// Login OTP fields
	LoginOtp           string     `bson:"login_otp,omitempty" json:"-"`
	LoginOtpExpiresAt  *time.Time `bson:"login_otp_expires_at,omitempty" json:"-"`
	LoginOtpMethodType string     `bson:"login_otp_method_type,omitempty" json:"-"`
}
