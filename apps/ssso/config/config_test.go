package config_test

import (
	"os"
	"testing"
	"time"

	"github.com/pilab-dev/shadow-sso/apps/ssso/config"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Helper to reset viper and environment variables for isolated tests
func resetConfigEnv(t *testing.T) {
	viper.Reset()
	// Unset environment variables that might interfere
	os.Unsetenv("SSSO_HTTP_ADDR")
	os.Unsetenv("SSSO_LOG_LEVEL")
	os.Unsetenv("SSSO_MONGO_URI")
	os.Unsetenv("SSSO_MONGO_DB_NAME")
	os.Unsetenv("SSSO_ISSUER_URL")
	os.Unsetenv("SSSO_KEY_ROTATION_INTERVAL")
	os.Unsetenv("SSSO_STORAGE_BACKEND")
	os.Unsetenv("SSSO_DTS_CLIENT_ADDRESS")
	os.Unsetenv("SSSO_DTS_CONNECT_TIMEOUT")
	os.Unsetenv("SSSO_DTS_DEFAULT_PKCE_TTL")
}

func TestLoadConfig_Defaults(t *testing.T) {
	resetConfigEnv(t)

	cfg, err := config.LoadConfig()
	require.NoError(t, err)

	assert.Equal(t, "0.0.0.0:8080", cfg.HTTPAddr)
	assert.Equal(t, "info", cfg.LogLevel)
	assert.Equal(t, "mongodb://localhost:27017", cfg.MongoURI)
	assert.Equal(t, "shadow_sso_db", cfg.MongoDBName)
	assert.Equal(t, "http://localhost:8080", cfg.IssuerURL)
	assert.Equal(t, 24*time.Hour, cfg.KeyRotationInterval) // Default is "24h"

	assert.Equal(t, config.StorageTypeMongoDB, cfg.StorageBackend) // Default "mongodb"
	assert.Equal(t, "localhost:50051", cfg.DTSClientAddress)
	assert.Equal(t, 5*time.Second, cfg.DTSConnectTimeout)  // Default "5s"
	assert.Equal(t, 10*time.Minute, cfg.DTSDefaultPKCETTL) // Default "10m"
}

func TestLoadConfig_EnvOverrides(t *testing.T) {
	resetConfigEnv(t)

	// Set environment variables
	os.Setenv("SSSO_HTTP_ADDR", "127.0.0.1:9090")
	os.Setenv("SSSO_LOG_LEVEL", "debug")
	os.Setenv("SSSO_MONGO_URI", "mongodb://testhost:27018")
	os.Setenv("SSSO_MONGO_DB_NAME", "test_db")
	os.Setenv("SSSO_ISSUER_URL", "https://sso.example.com")
	os.Setenv("SSSO_KEY_ROTATION_INTERVAL", "12h")

	os.Setenv("SSSO_STORAGE_BACKEND", "dts")
	os.Setenv("SSSO_DTS_CLIENT_ADDRESS", "dts.example.com:50052")
	os.Setenv("SSSO_DTS_CONNECT_TIMEOUT", "10s")
	os.Setenv("SSSO_DTS_DEFAULT_PKCE_TTL", "15m")

	// Clean up env vars after test
	defer func() {
		os.Unsetenv("SSSO_HTTP_ADDR")
		os.Unsetenv("SSSO_LOG_LEVEL")
		os.Unsetenv("SSSO_MONGO_URI")
		os.Unsetenv("SSSO_MONGO_DB_NAME")
		os.Unsetenv("SSSO_ISSUER_URL")
		os.Unsetenv("SSSO_KEY_ROTATION_INTERVAL")
		os.Unsetenv("SSSO_STORAGE_BACKEND")
		os.Unsetenv("SSSO_DTS_CLIENT_ADDRESS")
		os.Unsetenv("SSSO_DTS_CONNECT_TIMEOUT")
		os.Unsetenv("SSSO_DTS_DEFAULT_PKCE_TTL")
	}()

	cfg, err := config.LoadConfig()
	require.NoError(t, err)

	assert.Equal(t, "127.0.0.1:9090", cfg.HTTPAddr)
	assert.Equal(t, "debug", cfg.LogLevel)
	assert.Equal(t, "mongodb://testhost:27018", cfg.MongoURI)
	assert.Equal(t, "test_db", cfg.MongoDBName)
	assert.Equal(t, "https://sso.example.com", cfg.IssuerURL)
	assert.Equal(t, 12*time.Hour, cfg.KeyRotationInterval)

	assert.Equal(t, config.StorageTypeDTS, cfg.StorageBackend)
	assert.Equal(t, "dts.example.com:50052", cfg.DTSClientAddress)
	assert.Equal(t, 10*time.Second, cfg.DTSConnectTimeout)
	assert.Equal(t, 15*time.Minute, cfg.DTSDefaultPKCETTL)
}

func TestLoadConfig_InvalidStorageBackend(t *testing.T) {
	resetConfigEnv(t)
	os.Setenv("SSSO_STORAGE_BACKEND", "invalid_backend")
	defer os.Unsetenv("SSSO_STORAGE_BACKEND")

	cfg, err := config.LoadConfig()
	require.NoError(t, err)

	// The current LoadConfig logic with viper.GetString and then casting
	// means an invalid string will still be cast. Viper's Unmarshal might have already
	// set it to default if the env var wasn't directly mapped in a struct field that viper itself parses.
	// The current logic in LoadConfig for StorageBackend:
	// storageBackendString := viper.GetString("storage_backend")
	// ...
	// config.StorageBackend = StorageType(storageBackendString)
	// This will make config.StorageBackend = "invalid_backend".
	// This test highlights that we might want validation or for it to strictly default.
	// For now, testing current behavior.
	assert.Equal(t, config.StorageType("invalid_backend"), cfg.StorageBackend, "Should load the invalid string as StorageType for now")

	// If we want it to default on invalid, LoadConfig needs modification.
	// e.g.
	// if storageBackendString != string(StorageTypeMongoDB) && storageBackendString != string(StorageTypeDTS) {
	//    config.StorageBackend = StorageTypeMongoDB // Default
	// } else {
	//    config.StorageBackend = StorageType(storageBackendString)
	// }
}

func TestLoadConfig_InvalidDuration(t *testing.T) {
	resetConfigEnv(t)
	os.Setenv("SSSO_DTS_CONNECT_TIMEOUT", "not_a_duration")
	defer os.Unsetenv("SSSO_DTS_CONNECT_TIMEOUT")

	// Viper's behavior with time.Duration and mapstructure can be tricky for env vars.
	// If the env var is "not_a_duration", `viper.Unmarshal` might error or use default.
	// Let's see. The `mapstructure` hook for time.Duration usually expects strings like "5s", "10m".
	_, err := config.LoadConfig()
	// If Unmarshal fails due to duration parsing, err will be non-nil.
	// If it silently uses default, err is nil and value is default.
	require.Error(t, err, "Expected error due to invalid duration")
}
