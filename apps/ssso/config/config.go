package config

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/pilab-dev/shadow-sso/api"
	"github.com/rs/zerolog/log"
	"github.com/spf13/viper"
)

// Config holds all configuration for the SSO server.
type Config struct {
	HTTPAddr             string        `mapstructure:"http_addr"`
	MgmtHTTPAddr         string        `mapstructure:"mgmt_http_addr"`
	LogLevel             string        `mapstructure:"log_level"`
	MongoURI             string        `mapstructure:"mongo_uri"`
	MongoDBName          string        `mapstructure:"mongo_db_name"`
	IssuerURL            string        `mapstructure:"issuer_url"`
	SigningKeyPath       string        `mapstructure:"signing_key_path"` // Path to RSA private key PEM file
	KeyRotationInterval  time.Duration `mapstructure:"key_rotation_interval"`
	TokenCacheDefaultTTL time.Duration `mapstructure:"token_cache_default_ttl"`
	DefaultRedirectURI   string        `mapstructure:"default_redirect_uri"`

	// OIDC specific configurations that might be part of OpenIDProviderConfig
	NextJSLoginURL string `mapstructure:"nextjs_login_url"`

	// Storage and DTS specific configurations
	StorageBackend    StorageType   `mapstructure:"storage_backend"`
	DTSClientAddress  string        `mapstructure:"dts_client_address"`
	DTSConnectTimeout time.Duration `mapstructure:"dts_connect_timeout"`
	DTSDefaultPKCETTL time.Duration `mapstructure:"dts_default_pkce_ttl"`

	// SMS configuration
	TwilioAccountSID  string `mapstructure:"twilio_account_sid"`
	TwilioAuthToken   string `mapstructure:"twilio_auth_token"`
	TwilioPhoneNumber string `mapstructure:"twilio_phone_number"`

	// Email service configuration
	ResendAPIKey      string `mapstructure:"resend_api_key"`
	FromEmail         string `mapstructure:"from_email"`
	NextPublicBaseURL string `mapstructure:"next_public_base_url"`

	// Push notification service configuration
	FirebaseProjectID       string `mapstructure:"firebase_project_id"`
	FirebaseCredentialsPath string `mapstructure:"firebase_credentials_path"`

	// Configuration service encryption key
	ConfigEncryptionKey string `mapstructure:"config_encryption_key"`

	// Token signing
	TokenSigningKey     string `mapstructure:"token_signing_key"`
	TokenSigningKeyFile string `mapstructure:"token_signing_key_file"`

	// Initial admin bootstrap
	InitialAdminEnabled      bool   `mapstructure:"initial_admin_enabled"`
	InitialAdminEmail        string `mapstructure:"initial_admin_email"`
	InitialAdminPassword     string `mapstructure:"initial_admin_password"`
	InitialAdminFirstName    string `mapstructure:"initial_admin_first_name"`
	InitialAdminLastName     string `mapstructure:"initial_admin_last_name"`
	InitialAdminClientSecret string `mapstructure:"initial_admin_client_secret"`

	// JSON logging (false = pretty console for local dev)
	JSONLog bool `mapstructure:"json_log"`

	TracingEnabled      bool   `mapstructure:"tracing_enabled"`
	TracingOTLPEndpoint string `mapstructure:"tracing_otlp_endpoint"`

	// Brand customization
	BrandLogoURL          string `mapstructure:"brand_logo_url"`
	BrandOrganizationName string `mapstructure:"brand_organization_name"`
	BrandPrimaryColor     string `mapstructure:"brand_primary_color"`

	// Bootstrap token for admin client access (alternative to service account login)
	BootstrapToken string `mapstructure:"bootstrap_token"`

	// Rate limiting
	RateLimitMaxAttempts      int           `mapstructure:"rate_limit_max_attempts"`
	RateLimitLockoutDuration  time.Duration `mapstructure:"rate_limit_lockout_duration"`

	// CORS configuration
	AllowedOrigins []string `mapstructure:"allowed_origins"`
}

// StorageType defines the type of storage backend to use.
type StorageType string

const (
	StorageTypeMongoDB StorageType = "mongodb"
	StorageTypeDTS     StorageType = "dts"
)

// ToOpenIDProviderConfig converts the internal app configuration to a public api.OpenIDProviderConfig.
// This function maps relevant fields from the internal config to the external OIDC provider config.
func (c *Config) ToOpenIDProviderConfig() *api.OpenIDProviderConfig {
	// Create a default config - NewDefaultConfig was removed, so we initialize manually
	oidcConfig := &api.OpenIDProviderConfig{
		Issuer:            c.IssuerURL,
		AccessTokenTTL:    15 * time.Minute, // Default
		RefreshTokenTTL:   24 * time.Hour,   // Default
		AuthCodeTTL:       10 * time.Minute, // Default
		IDTokenTTL:        15 * time.Minute, // Default
		SessionTTL:        24 * time.Hour,   // Default
		KeyRotationPeriod: c.KeyRotationInterval,
		NextJSLoginURL:    c.NextJSLoginURL,
		// Set default enabled endpoints, grant types, etc.
		EnabledEndpoints: api.EndpointConfig{
			Authorization:       true,
			Token:               true,
			UserInfo:            true,
			JWKS:                true,
			Revocation:          true,
			Introspection:       true,
			DeviceAuthorization: true,
		},
		EnabledGrantTypes: api.GrantTypesConfig{
			AuthorizationCode: true,
			RefreshToken:      true,
			ClientCredentials: true,
			Password:          true,
			DeviceCode:        true,
		},
		SecurityConfig: api.SecurityConfig{
			AllowedSigningAlgs:  []string{"RS256", "HS256"},
			PasswordHashingCost: 10,
		},
		TokenConfig: api.TokenConfig{
			AccessTokenFormat:      "jwt",
			SupportedResponseTypes: []string{"code"},
		},
		PKCEConfig: api.PKCEConfig{
			Enabled:          true,
			SupportedMethods: []string{"S256"},
		},
	}

	// Override defaults with values from the app's config
	oidcConfig.AccessTokenTTL = c.TokenCacheDefaultTTL            // Assuming this is the desired mapping
	oidcConfig.RefreshTokenTTL = c.TokenCacheDefaultTTL * 24 * 30 // Example mapping, adjust as needed
	oidcConfig.AuthCodeTTL = 10 * time.Minute                     // Hardcoded default, can be from config if exposed
	oidcConfig.IDTokenTTL = c.TokenCacheDefaultTTL
	oidcConfig.SessionTTL = c.KeyRotationInterval // Assuming session TTL can be linked to this or another config entry
	oidcConfig.KeyRotationPeriod = c.KeyRotationInterval
	oidcConfig.NextJSLoginURL = c.NextJSLoginURL

	// Map other fields from c.Config to oidcConfig, especially those in SecurityConfig, TokenConfig, etc.
	// For now, many of these will retain the NewDefaultConfig values unless explicitly mapped here.
	// For example, PasswordHashingCost can be mapped:
	// oidcConfig.SecurityConfig.PasswordHashingCost = 10 // Assuming a default or from config.
	// As this internal config struct doesn't expose many granular OIDC config fields,
	// NewDefaultConfig's values will largely be used for those.

	// Example of mapping a security config field if it exists in internal Config
	// if c.PasswordHashingCost > 0 { // Assuming PasswordHashingCost is exposed in config.Config
	// 	oidcConfig.SecurityConfig.PasswordHashingCost = c.PasswordHashingCost
	// }

	return oidcConfig
}

// LoadConfig loads configuration from file and environment variables.
func LoadConfig() (config Config, err error) {
	viper.SetConfigName("sso_config") // Name of config file (without extension)
	viper.SetConfigType("yaml")       // REQUIRED if the config file does not have the extension in the name
	viper.AddConfigPath(".")          // Optionally look for config in the working directory
	viper.AddConfigPath("/etc/sso/")  // Path to look for the config file in
	viper.AddConfigPath("$HOME/.sso") // Call multiple times to add many search paths

	// Environment variable binding
	viper.SetEnvPrefix("SSSO") // Will search for SSSO_HTTP_ADDR, SSSO_MONGO_URI etc.
	viper.AutomaticEnv()
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))

	// Default values for original SSSO settings
	viper.SetDefault("http_addr", "0.0.0.0:8080")
	viper.SetDefault("mgmt_http_addr", ":5000")
	viper.SetDefault("log_level", "info")
	viper.SetDefault("mongo_uri", "mongodb://localhost:27017")
	viper.SetDefault("mongo_db_name", "shadow_sso_db")
	viper.SetDefault("issuer_url", "http://localhost:8080") // Default to HTTP for local dev
	viper.SetDefault("key_rotation_interval", "24h")
	viper.SetDefault("default_redirect_uri", "http://localhost:3000/login")
	viper.SetDefault("token_cache_default_ttl", "1h")
	// signing_key_path has no default, should be provided or generated on first run.
	// nextjs_login_url has no default, should be configured if UI flow is used.

	// Default values for new storage and DTS settings
	// Note: SSSO_STORAGE_BACKEND will be used for environment variable
	viper.SetDefault("storage_backend", string(StorageTypeMongoDB))
	viper.SetDefault("dts_client_address", "localhost:50051") // Default for local dev
	viper.SetDefault("dts_connect_timeout", "5s")             // Consistent with time.ParseDuration
	viper.SetDefault("dts_default_pkce_ttl", "10m")           // Consistent with time.ParseDuration

	// Default values for SMS configuration
	viper.SetDefault("twilio_account_sid", "")
	viper.SetDefault("twilio_auth_token", "")
	viper.SetDefault("twilio_phone_number", "")

	// Default values for email service configuration
	viper.SetDefault("resend_api_key", "")
	viper.SetDefault("from_email", "")
	viper.SetDefault("next_public_base_url", "")

	// Default values for push notification service configuration
	viper.SetDefault("firebase_project_id", "")
	viper.SetDefault("firebase_credentials_path", "")

	viper.SetDefault("initial_admin_enabled", false)
	viper.SetDefault("initial_admin_email", "")
	viper.SetDefault("initial_admin_password", "")
	viper.SetDefault("initial_admin_first_name", "Admin")
	viper.SetDefault("initial_admin_last_name", "User")
	viper.SetDefault("initial_admin_client_secret", "")
	viper.SetDefault("bootstrap_token", "")
	viper.SetDefault("json_log", false)
	viper.SetDefault("tracing_enabled", false)
	viper.SetDefault("tracing_otlp_endpoint", "")

	viper.SetDefault("brand_logo_url", "")
	viper.SetDefault("brand_organization_name", "")
	viper.SetDefault("brand_primary_color", "")
	viper.SetDefault("rate_limit_max_attempts", 5)
	viper.SetDefault("rate_limit_lockout_duration", "15m")
	viper.SetDefault("allowed_origins", []string{"*"})

	// Explicitly bind env vars so viper.Unmarshal picks them up
	_ = viper.BindEnv("mgmt_http_addr")
	_ = viper.BindEnv("config_encryption_key")
	_ = viper.BindEnv("signing_key_path")
	viper.BindEnv("token_signing_key")
	viper.BindEnv("initial_admin_enabled")
	viper.BindEnv("initial_admin_email")
	viper.BindEnv("initial_admin_password")
	viper.BindEnv("initial_admin_first_name")
	viper.BindEnv("initial_admin_last_name")
	viper.BindEnv("initial_admin_client_secret")
	viper.BindEnv("bootstrap_token")
	viper.BindEnv("json_log")
	viper.BindEnv("tracing_enabled")
	viper.BindEnv("tracing_otlp_endpoint")
	viper.BindEnv("allowed_origins")

	if errRead := viper.ReadInConfig(); errRead != nil {
		if _, ok := errRead.(viper.ConfigFileNotFoundError); ok {
			// Config file not found; ignore error if desired or load from env only
			// For now, we'll proceed with defaults and env vars if file not found
		} else {
			// Config file was found but another error was produced
			return Config{}, errRead
		}
	}

	err = viper.Unmarshal(&config)
	if err != nil {
		return
	}

	if config.ConfigEncryptionKey == "" {
		if config.JSONLog || config.InitialAdminEnabled {
			return Config{}, fmt.Errorf("FATAL: config_encryption_key is required. Set SSSO_CONFIG_ENCRYPTION_KEY environment variable")
		}
		key := make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			return Config{}, fmt.Errorf("failed to generate encryption key: %w", err)
		}
		config.ConfigEncryptionKey = hex.EncodeToString(key)
		log.Warn().Msgf("No SSSO_CONFIG_ENCRYPTION_KEY set — auto-generated ephemeral key for dev session: %s", config.ConfigEncryptionKey)
	}

	// Viper doesn't automatically convert string to custom types like StorageType
	// when unmarshalling from environment variables that were not in the config file.
	// We need to handle StorageBackend specifically if it comes from env var directly.
	// Also, viper needs explicit GetString for env vars not in file or defaults for type consistency.
	// For durations, viper can parse strings like "5s" or "10m" into time.Duration if mapstructure tags are correct
	// and the values in config file or defaults are strings that time.ParseDuration can handle.

	// Ensure StorageBackend is correctly parsed
	// If SSSO_STORAGE_BACKEND is set, viper.AutomaticEnv should pick it up.
	// We then cast it to StorageType.
	storageBackendString := viper.GetString("storage_backend")
	if storageBackendString != string(StorageTypeMongoDB) && storageBackendString != string(StorageTypeDTS) {
		// If an invalid value was somehow set (e.g. directly in a yaml file with a typo, and not caught by viper)
		// or if viper.GetString returns "" when not set (instead of default - depends on viper version/behavior)
		// It's safer to re-apply default if the value is not one of the expected.
		// However, viper.Unmarshal should have applied the default if the key was missing.
		// This is more of a safeguard or if custom validation is needed.
		// For now, assume viper handles defaults correctly and unmarshals the string.
		// The type cast below will work.
	}
	config.StorageBackend = StorageType(storageBackendString)

	// For time.Duration fields, viper/mapstructure should handle parsing from strings like "5s", "24h"
	// Ensure defaults are also in this string format.
	// If issues arise with env var overrides for durations, manual parsing might be needed:
	// e.g., config.DTSConnectTimeout = viper.GetDuration("dts_connect_timeout")
	// This requires viper.GetDuration to be used instead of relying on Unmarshal for these fields
	// if env vars are providing simple numbers instead of "5s" strings.
	// The current setup with AutomaticEnv and Unmarshal should work if env vars are SSSO_DTS_CONNECT_TIMEOUT=5s

	return
}
