package config

import (
	"fmt"
	"strings"

	"github.com/spf13/viper"
)

// ServerConfig holds all configuration for the server.
// Tags use mapstructure for Viper unmarshalling and env for environment variable binding.
type ServerConfig struct {
	HTTPPort           string `mapstructure:"HTTP_PORT"`
	GRPCPort           string `mapstructure:"GRPC_PORT"` // For ConnectRPC or gRPC
	MongoURI           string `mapstructure:"MONGO_URI"`
	MongoDBName        string `mapstructure:"MONGO_DB_NAME"`
	LogLevel           string `mapstructure:"LOG_LEVEL"`
	LogPretty          bool   `mapstructure:"LOG_PRETTY"`
	OtelExporterEndpoint string `mapstructure:"OTEL_EXPORTER_ENDPOINT"` // e.g., for Jaeger/OTLP
	OtelServiceName    string `mapstructure:"OTEL_SERVICE_NAME"`

	// Example: JWT configuration
	JWTSecretKey      string `mapstructure:"JWT_SECRET_KEY"`
	AccessTokenTTLMin int    `mapstructure:"ACCESS_TOKEN_TTL_MIN"`
	RefreshTokenTTLHour int  `mapstructure:"REFRESH_TOKEN_TTL_HOUR"`

	// Add other configurations as needed:
	// - OIDC provider settings (if this server acts as one)
	// - Default client settings
	// - Rate limiting settings
	// - etc.
}

// LoadConfig reads configuration from file, environment variables, and defaults.
func LoadConfig() (*ServerConfig, error) {
	v := viper.New()

	// Set configuration file name and type
	v.SetConfigName("config") // name of config file (without extension)
	v.SetConfigType("yaml")   // REQUIRED if the config file does not have the extension in the name

	// Set search paths for the configuration file
	v.AddConfigPath("/etc/shadow-sso/")  // Path to look for the config file in
	v.AddConfigPath("$HOME/.shadow-sso") // Call multiple times to add many search paths
	v.AddConfigPath(".")                 // Optionally look for config in the working directory

	// Read environment variables
	v.AutomaticEnv()
	// For nested env vars like PARENT.CHILD -> PARENT_CHILD
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))

	// Set default values
	v.SetDefault("HTTP_PORT", "8080")
	v.SetDefault("GRPC_PORT", "8081")
	v.SetDefault("MONGO_URI", "mongodb://localhost:27017/shadow_sso_dev")
	v.SetDefault("MONGO_DB_NAME", "shadow_sso_dev")
	v.SetDefault("LOG_LEVEL", "info")
	v.SetDefault("LOG_PRETTY", true)
	v.SetDefault("OTEL_SERVICE_NAME", "shadow-sso-server")
	v.SetDefault("JWT_SECRET_KEY", "a_very_secret_jwt_key_change_me") // CHANGE IN PRODUCTION
	v.SetDefault("ACCESS_TOKEN_TTL_MIN", 60)    // 1 hour
	v.SetDefault("REFRESH_TOKEN_TTL_HOUR", 720) // 30 days

	// Attempt to read the config file
	if err := v.ReadInConfig(); err != nil {
		// ConfigFileNotFoundError is acceptable, means we use defaults/env vars.
		// Other errors (e.g., permission issues, malformed config) should be returned.
		var configFileNotFoundError viper.ConfigFileNotFoundError
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			// This is a real error reading the config file if it was found
			return nil, fmt.Errorf("error reading config file: %w", err)
		}
		// If it is ConfigFileNotFoundError, we log it later if needed, but proceed with defaults/env.
	}

	// Unmarshal the configuration into the ServerConfig struct
	var cfg ServerConfig
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("unable to decode config into struct: %w", err)
	}

	return &cfg, nil
}
