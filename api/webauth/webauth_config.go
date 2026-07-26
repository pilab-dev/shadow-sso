package webauth

import "time"

// Config holds configuration for the web authentication UI.
// Brand* fields control visual branding of the login/consent pages.
// RateLimit* fields configure brute-force protection.
type Config struct {
	// BrandLogoURL is the URL of the organization logo displayed on login pages.
	BrandLogoURL string
	// BrandOrganizationName is the organization name shown on login pages.
	BrandOrganizationName string
	// BrandPrimaryColor is the CSS primary color used for buttons and accents.
	BrandPrimaryColor string

	// RateLimitMaxAttempts is the number of failed login attempts before lockout.
	// Default: 5
	RateLimitMaxAttempts int
	// RateLimitLockoutDuration is how long an account/IP is locked after exceeding max attempts.
	// Default: 15m
	RateLimitLockoutDuration time.Duration
}

// DefaultConfig returns a Config with sensible defaults.
func DefaultConfig() *Config {
	return &Config{
		BrandLogoURL:             "",
		BrandOrganizationName:    "Shadow SSO",
		BrandPrimaryColor:        "#007bff",
		RateLimitMaxAttempts:     5,
		RateLimitLockoutDuration: 15 * time.Minute,
	}
}
