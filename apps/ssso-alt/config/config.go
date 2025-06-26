package config

import (
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	orig_config "github.com/pilab-dev/ssso/apps/ssso/config" // Reuse parts of original config
)

// StorageType defines the type of storage backend to use.
type StorageType string

const (
	StorageTypeMongoDB StorageType = "mongodb"
	StorageTypeDTS     StorageType = "dts"
)

// Config extends the original SSSO config with DTS specific settings
// and a selector for storage type.
type Config struct {
	orig_config.Config // Embed original config

	StorageBackend StorageType `json:"storage_backend"` // "mongodb" or "dts"
	DTSClientAddress string      `json:"dts_client_address"` // e.g., "localhost:50051"
	DTSConnectTimeout time.Duration `json:"dts_connect_timeout"`
	DTSDefaultPKCETTL time.Duration `json:"dts_default_pkce_ttl"` // For PKCE store adapter
}

// LoadConfig loads configuration for the ssso-alt service.
// It first loads the base SSSO config and then overrides/adds ssso-alt specific ones.
func LoadConfig() *Config {
	baseCfg := orig_config.LoadConfig() // Load SSSO's default config

	altCfg := &Config{
		Config: *baseCfg, // Copy base configuration
	}

	altCfg.StorageBackend = StorageType(strings.ToLower(getEnv("SSSO_ALT_STORAGE_BACKEND", string(StorageTypeMongoDB))))
	altCfg.DTSClientAddress = getEnv("SSSO_DTS_CLIENT_ADDRESS", "localhost:50051") // Default for local dev
	altCfg.DTSConnectTimeout = getEnvDurationSeconds("SSSO_DTS_CONNECT_TIMEOUT_SECONDS", "5")
	altCfg.DTSDefaultPKCETTL = getEnvDurationMinutes("SSSO_DTS_DEFAULT_PKCE_TTL_MINUTES", "10")


	// Example: Potentially override some base settings if needed for ssso-alt
	// if altCfg.StorageBackend == StorageTypeDTS {
	//    log.Println("DTS storage backend selected. Certain MongoDB related settings might be ignored.")
	// }

	log.Printf("SSSO-Alt Configuration:")
	log.Printf("  Storage Backend: %s", altCfg.StorageBackend)
	if altCfg.StorageBackend == StorageTypeDTS {
		log.Printf("  DTS Client Address: %s", altCfg.DTSClientAddress)
		log.Printf("  DTS Connect Timeout: %v", altCfg.DTSConnectTimeout)
		log.Printf("  DTS Default PKCE TTL: %v", altCfg.DTSDefaultPKCETTL)
	}

	return altCfg
}

// Helper functions (can be shared or duplicated from original config if not importable easily)
func getEnv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return fallback
}

// getEnvDurationSeconds reads an environment variable as an integer and returns it as time.Duration in seconds.
func getEnvDurationSeconds(key, fallbackSeconds string) time.Duration {
	valStr := fallbackSeconds
	if value, ok := os.LookupEnv(key); ok {
		valStr = value
	}

	seconds, err := strconv.ParseInt(valStr, 10, 64)
	if err != nil {
		log.Printf("Invalid duration value for %s (expected seconds): '%s'. Using default: %s seconds. Error: %v", key, valStr, fallbackSeconds, err)
		fallbackParsed, _ := strconv.ParseInt(fallbackSeconds, 10, 64)
		return time.Duration(fallbackParsed) * time.Second
	}
	return time.Duration(seconds) * time.Second
}

// getEnvDurationMinutes reads an environment variable as an integer and returns it as time.Duration in minutes.
func getEnvDurationMinutes(key, fallbackMinutes string) time.Duration {
	valStr := fallbackMinutes
	if value, ok := os.LookupEnv(key); ok {
		valStr = value
	}

	minutes, err := strconv.ParseInt(valStr, 10, 64)
	if err != nil {
		log.Printf("Invalid duration value for %s (expected minutes): '%s'. Using default: %s minutes. Error: %v", key, valStr, fallbackMinutes, err)
		fallbackParsed, _ := strconv.ParseInt(fallbackMinutes, 10, 64)
		return time.Duration(fallbackParsed) * time.Minute
	}
	return time.Duration(minutes) * time.Minute
}


// Example: getEnvBool
// func getEnvBool(key string, fallback bool) bool {
// 	if value, ok := os.LookupEnv(key); ok {
// 		boolVal, err := strconv.ParseBool(value)
// 		if err == nil {
// 			return boolVal
// 		}
// 		log.Printf("Invalid boolean value for %s: %s. Using default: %t. Error: %v", key, value, fallback, err)
// 	}
// 	return fallback
// }

func init() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
}
