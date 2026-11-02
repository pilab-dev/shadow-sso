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

// The identity sources a User record can come from.
const (
	// SourceLocal is MongoDB: the record holds the identity, the SSO state
	// and the password hash. It is the default for standalone ShadowSSO.
	SourceLocal = "local"
	// SourceDirectory is an external directory that owns the password and the
	// attributes; PiRectory is the first one, and names itself `pirectory`.
	// Such a record holds only SSO-owned state, keyed by DirectoryID.
	SourceDirectory = "pirectory"
)

// IsDirectory reports whether the user's identity is owned by an external
// directory, in which case ShadowSSO must not store or change its password.
func (u *User) IsDirectory() bool {
	return u != nil && u.Source != "" && u.Source != SourceLocal
}

// MfaMethodType defines the type of MFA method.
type MfaMethodType string

const (
	MfaMethodTypeTOTP     MfaMethodType = "TOTP"
	MfaMethodTypeSMS      MfaMethodType = "SMS"
	MfaMethodTypeEmail    MfaMethodType = "EMAIL"
	MfaMethodTypeWebAuthn MfaMethodType = "WEBAUTHN"
	MfaMethodTypeYubico   MfaMethodType = "YUBICO"
	MfaMethodTypePush     MfaMethodType = "PUSH"
	MfaMethodTypeNone     MfaMethodType = "NONE"
)

// MfaMethod represents an MFA method for a user.
type MfaMethod struct {
	ID           string        `bson:"id" json:"id"`
	Type         MfaMethodType `bson:"type" json:"type"`
	Secret       string        `bson:"secret,omitempty" json:"-"`
	Verified     bool          `bson:"verified" json:"verified"`
	CreatedAt    time.Time     `bson:"created_at" json:"created_at"`
	Name         string        `bson:"name,omitempty" json:"name"`
	// WebAuthn/passkey specific fields (stored in Secret as well for the
	// full credential record; these are convenience projections).
	CredentialID string `bson:"credential_id,omitempty" json:"credential_id,omitempty"`
	Counter      int32  `bson:"counter,omitempty" json:"counter,omitempty"`
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
	// CredentialJSON is the serialized go-webauthn Credential (public key, flags, sign counter).
	// It is authoritative for verification; the flat fields above are kept for display/legacy use.
	CredentialJSON string `bson:"credential_json,omitempty" json:"-"`
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
	ID           string     `bson:"_id,omitempty" json:"id,omitempty"`
	Email        string     `bson:"email,unique" json:"email"`
	PasswordHash string     `bson:"password_hash" json:"-"`
	Status       UserStatus `bson:"status" json:"status"`
	// Source is where the identity record comes from; empty means local.
	// SourceDirectory identities keep no password here: PiRectory owns it.
	Source string `bson:"source,omitempty" json:"source,omitempty"`
	// DirectoryID is the directory object id (the objectGUID) of a
	// SourceDirectory identity. It is the OIDC subject and the key this
	// record's SSO-owned state is stored under.
	DirectoryID string `bson:"directory_id,omitempty" json:"directory_id,omitempty"`
	// Groups are the directory groups the identity belongs to, by name.
	Groups []string `bson:"groups,omitempty" json:"groups,omitempty"`
	// Attributes are the directory attributes projected for claims, keyed by
	// attribute name.
	Attributes map[string][]string `bson:"attributes,omitempty" json:"attributes,omitempty"`
	// USN is the directory update sequence the projection was read at.
	USN                 int64               `bson:"usn,omitempty" json:"usn,omitempty"`
	FirstName           string              `bson:"first_name,omitempty" json:"first_name,omitempty"`
	LastName            string              `bson:"last_name,omitempty" json:"last_name,omitempty"`
	Roles               []string            `bson:"roles,omitempty" json:"roles,omitempty"`
	ClientRoles         map[string][]string `bson:"client_roles,omitempty" json:"client_roles,omitempty"`
	CreatedAt           time.Time           `bson:"created_at" json:"created_at"`
	UpdatedAt           time.Time           `bson:"updated_at" json:"updated_at"`
	LastLoginAt         *time.Time          `bson:"last_login_at,omitempty" json:"last_login_at,omitempty"`
	FailedLoginAttempts int                 `bson:"failed_login_attempts,omitempty" json:"failed_login_attempts,omitempty"`
	LastFailedLoginTime *time.Time          `bson:"last_failed_login_time,omitempty" json:"-"`

	// MFA Methods (multiple methods supported)
	MfaMethods []MfaMethod `bson:"mfa_methods,omitempty" json:"mfa_methods,omitempty"`

	// WebAuthn Devices
	WebAuthnDevices []WebAuthnDevice `bson:"webauthn_devices,omitempty" json:"webauthn_devices,omitempty"`

	// MFARequired forces this user to complete a second factor at login. When
	// the user has no usable factor yet, the login flow sends them to the
	// enrollment page instead of completing the sign-in.
	MFARequired bool `bson:"mfa_required,omitempty" json:"mfa_required,omitempty"`

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

	// RequiredActions are steps the user must complete at next login, before any
	// authorization code is issued (Keycloak "required actions").
	RequiredActions []string `bson:"required_actions,omitempty" json:"required_actions,omitempty"`

	// Login OTP fields
	LoginOtp           string     `bson:"login_otp,omitempty" json:"-"`
	LoginOtpExpiresAt  *time.Time `bson:"login_otp_expires_at,omitempty" json:"-"`
	LoginOtpMethodType string     `bson:"login_otp_method_type,omitempty" json:"-"`
}

// Required action aliases.
const (
	RequiredActionUpdatePassword = "UPDATE_PASSWORD"
	RequiredActionConfigureTOTP  = "CONFIGURE_TOTP"
	RequiredActionVerifyEmail    = "VERIFY_EMAIL"
	RequiredActionUpdateProfile  = "UPDATE_PROFILE"
	RequiredActionTerms          = "TERMS_AND_CONDITIONS"
)

// KnownRequiredActions lists every alias in evaluation order.
var KnownRequiredActions = []string{
	RequiredActionUpdatePassword,
	RequiredActionConfigureTOTP,
	RequiredActionVerifyEmail,
	RequiredActionUpdateProfile,
	RequiredActionTerms,
}

// IsKnownRequiredAction reports whether alias is a recognised required action.
func IsKnownRequiredAction(alias string) bool {
	for _, a := range KnownRequiredActions {
		if a == alias {
			return true
		}
	}
	return false
}

// HasRequiredAction reports whether the user has the given action pending.
func (u *User) HasRequiredAction(alias string) bool {
	for _, a := range u.RequiredActions {
		if a == alias {
			return true
		}
	}
	return false
}

// AddRequiredAction adds alias if not already present.
func (u *User) AddRequiredAction(alias string) {
	if !u.HasRequiredAction(alias) {
		u.RequiredActions = append(u.RequiredActions, alias)
	}
}

// RemoveRequiredAction removes alias if present.
func (u *User) RemoveRequiredAction(alias string) {
	out := u.RequiredActions[:0:0]
	for _, a := range u.RequiredActions {
		if a != alias {
			out = append(out, a)
		}
	}
	u.RequiredActions = out
}
