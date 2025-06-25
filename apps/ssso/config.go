package main

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

	// OIDC specific configurations that might be part of OpenIDProviderConfig
	NextJSLoginURL string `mapstructure:"nextjs_login_url"`
}

// LoadConfig loads configuration from file and environment variables.
func LoadConfig() (config Config, err error) {
	viper.SetConfigName("sso_config") // Name of config file (without extension)
	viper.SetConfigType("yaml")      // REQUIRED if the config file does not have the extension in the name
	viper.AddConfigPath(".")         // Optionally look for config in the working directory
	viper.AddConfigPath("/etc/sso/") // Path to look for the config file in
	viper.AddConfigPath("$HOME/.sso") // Call multiple times to add many search paths

	// Environment variable binding
	viper.SetEnvPrefix("SSSO") // Will search for SSSO_HTTP_ADDR, SSSO_MONGO_URI etc.
	viper.AutomaticEnv()
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))

	// Default values
	viper.SetDefault("http_addr", "0.0.0.0:8080")
	viper.SetDefault("log_level", "info")
	viper.SetDefault("mongo_uri", "mongodb://localhost:27017")
	viper.SetDefault("mongo_db_name", "shadow_sso_db")
	viper.SetDefault("issuer_url", "http://localhost:8080") // Default to HTTP for local dev
	viper.SetDefault("key_rotation_interval", "24h")
	// signing_key_path has no default, should be provided or generated on first run.
	// nextjs_login_url has no default, should be configured if UI flow is used.

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
	return
}
