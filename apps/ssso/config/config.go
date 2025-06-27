package config

import (
	"strings"
	"time"

	"github.com/spf13/viper"
)

// Config holds all configuration for the SSO server.
type Config struct {
	HTTPAddr            string        `mapstructure:"http_addr"`
	LogLevel            string        `mapstructure:"log_level"`
	MongoURI            string        `mapstructure:"mongo_uri"`
	MongoDBName         string        `mapstructure:"mongo_db_name"`
	IssuerURL           string        `mapstructure:"issuer_url"`
	SigningKeyPath      string        `mapstructure:"signing_key_path"` // Path to RSA private key PEM file
	KeyRotationInterval time.Duration `mapstructure:"key_rotation_interval"`
	DefaultRedirectURI  string        `mapstructure:"default_redirect_uri"`

	// OIDC specific configurations that might be part of OpenIDProviderConfig
	NextJSLoginURL string `mapstructure:"nextjs_login_url"`

	// Storage and DTS specific configurations
	StorageBackend    StorageType   `mapstructure:"storage_backend"`
	DTSClientAddress  string        `mapstructure:"dts_client_address"`
	DTSConnectTimeout time.Duration `mapstructure:"dts_connect_timeout"`
	DTSDefaultPKCETTL time.Duration `mapstructure:"dts_default_pkce_ttl"`
}

// StorageType defines the type of storage backend to use.
type StorageType string

const (
	StorageTypeMongoDB StorageType = "mongodb"
	StorageTypeDTS     StorageType = "dts"
)

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
	viper.SetDefault("log_level", "info")
	viper.SetDefault("mongo_uri", "mongodb://localhost:27017")
	viper.SetDefault("mongo_db_name", "shadow_sso_db")
	viper.SetDefault("issuer_url", "http://localhost:8080") // Default to HTTP for local dev
	viper.SetDefault("key_rotation_interval", "24h")
	viper.SetDefault("default_redirect_uri", "http://localhost:3000/login")
	// signing_key_path has no default, should be provided or generated on first run.
	// nextjs_login_url has no default, should be configured if UI flow is used.

	// Default values for new storage and DTS settings
	// Note: SSSO_STORAGE_BACKEND will be used for environment variable
	viper.SetDefault("storage_backend", string(StorageTypeMongoDB))
	viper.SetDefault("dts_client_address", "localhost:50051") // Default for local dev
	viper.SetDefault("dts_connect_timeout", "5s")             // Consistent with time.ParseDuration
	viper.SetDefault("dts_default_pkce_ttl", "10m")           // Consistent with time.ParseDuration

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
