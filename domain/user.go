package domain

import (
	"errors" // Added for ErrUserNotFound
	"time"
)

// ErrUserNotFound is returned when a user is not found in the repository.
var ErrUserNotFound = errors.New("user not found")

// UserStatus defines the possible statuses of a user account.
type UserStatus string

const (
	UserStatusActive   UserStatus = "ACTIVE"
	UserStatusLocked   UserStatus = "LOCKED"
	UserStatusPending  UserStatus = "PENDING_ACTIVATION" // If email verification is implemented
)

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
	TwoFactorMethod       string   `bson:"two_factor_method,omitempty" json:"two_factor_method,omitempty"` // e.g., "TOTP", "NONE"
	TwoFactorSecret       string   `bson:"two_factor_secret,omitempty" json:"-"`                            // Encrypted, never send via JSON
	TwoFactorRecoveryCodes []string `bson:"two_factor_recovery_codes,omitempty" json:"-"`                    // Hashed, never send via JSON
}
