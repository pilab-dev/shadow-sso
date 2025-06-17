package domain

import "time"

// UserStatus defines the possible statuses of a user account.
type UserStatus string

const (
	UserStatusActive   UserStatus = "ACTIVE"
	UserStatusLocked   UserStatus = "LOCKED"
	UserStatusPending  UserStatus = "PENDING_ACTIVATION" // If email verification is implemented
)

// User represents a user in the system.
type User struct {
	ID                string     `bson:"_id,omitempty"` // MongoDB ID
	Email             string     `bson:"email,unique"`
	PasswordHash      string     `bson:"password_hash"`
	Status            UserStatus `bson:"status"`
	FirstName         string     `bson:"first_name,omitempty"`
	LastName          string     `bson:"last_name,omitempty"`
	CreatedAt         time.Time  `bson:"created_at"`
	UpdatedAt         time.Time  `bson:"updated_at"`
	LastLoginAt       *time.Time `bson:"last_login_at,omitempty"`
	FailedLoginAttempts int    `bson:"failed_login_attempts,omitempty"`
}
