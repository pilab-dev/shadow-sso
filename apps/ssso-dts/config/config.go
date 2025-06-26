package config

import (
	"log"
	"os"
	"strconv"
	"time"
)

// Config holds the configuration for the DTS service.
type Config struct {
	GRPCServerAddress   string
	BBoltDBPath         string
	DefaultTTL          time.Duration
	CleanupInterval     time.Duration
	MaxMsgSize          int
}

// LoadConfig loads configuration from environment variables or defaults.
func LoadConfig() *Config {
	return &Config{
		GRPCServerAddress: getEnv("DTS_GRPC_SERVER_ADDRESS", "0.0.0.0:50051"),
		BBoltDBPath:       getEnv("DTS_BBOLTDB_PATH", "/data/dts.db"), // Standard place for data in containers
		DefaultTTL:        getEnvDuration("DTS_DEFAULT_TTL_SECONDS", "3600"),       // Default to 1 hour
		CleanupInterval:   getEnvDuration("DTS_CLEANUP_INTERVAL_SECONDS", "600"), // Default to 10 minutes
		MaxMsgSize:        getEnvInt("DTS_MAX_MSG_SIZE_BYTES", "16777216"), // Default to 16MB (16 * 1024 * 1024)
	}
}

func getEnv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		log.Printf("Loaded %s from environment: %s", key, value)
		return value
	}
	log.Printf("Using default value for %s: %s", key, fallback)
	return fallback
}

func getEnvDuration(key, fallbackSecondsStr string) time.Duration {
	valStr := fallbackSecondsStr
	if value, ok := os.LookupEnv(key); ok {
		valStr = value
		log.Printf("Loaded %s from environment: %s seconds", key, valStr)
	} else {
		log.Printf("Using default value for %s: %s seconds", key, fallbackSecondsStr)
	}

	seconds, err := strconv.ParseInt(valStr, 10, 64)
	if err != nil {
		log.Printf("Invalid duration value for %s: '%s'. Using default: %s seconds. Error: %v", key, valStr, fallbackSecondsStr, err)
		fallbackSeconds, _ := strconv.ParseInt(fallbackSecondsStr, 10, 64) // Assuming fallback is always valid
		return time.Duration(fallbackSeconds) * time.Second
	}
	return time.Duration(seconds) * time.Second
}

func getEnvInt(key, fallbackStr string) int {
	valStr := fallbackStr
	if value, ok := os.LookupEnv(key); ok {
		valStr = value
		log.Printf("Loaded %s from environment: %s", key, valStr)
	} else {
		log.Printf("Using default value for %s: %s", key, fallbackStr)
	}

	intValue, err := strconv.Atoi(valStr)
	if err != nil {
		log.Printf("Invalid integer value for %s: '%s'. Using default: %s. Error: %v", key, valStr, fallbackStr, err)
		fallbackIntValue, _ := strconv.Atoi(fallbackStr) // Assuming fallback is always valid
		return fallbackIntValue
	}
	return intValue
}
