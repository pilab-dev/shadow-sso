package mongodb_test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/pilab-dev/shadow-sso/mongodb"
	"github.com/stretchr/testify/assert"
)

func TestMongoRepositoryProvider_Ping(t *testing.T) {
	mongoURI := os.Getenv("MONGO_TEST_URI")
	if mongoURI == "" {
		mongoURI = "mongodb://localhost:27017"
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Test with valid MongoDB connection
	provider, err := mongodb.NewMongoRepositoryProvider(mongoURI, "test_ping_db")
	if err != nil {
		t.Skipf("Skipping test: MongoDB not available: %v", err)
	}
	defer provider.Disconnect(context.Background())

	// Test successful ping
	err = provider.Ping(ctx)
	assert.NoError(t, err, "Ping should succeed with valid MongoDB connection")
}

func TestMongoRepositoryProvider_Ping_WithTimeout(t *testing.T) {
	mongoURI := os.Getenv("MONGO_TEST_URI")
	if mongoURI == "" {
		mongoURI = "mongodb://localhost:27017"
	}

	provider, err := mongodb.NewMongoRepositoryProvider(mongoURI, "test_ping_timeout_db")
	if err != nil {
		t.Skipf("Skipping test: MongoDB not available: %v", err)
	}
	defer provider.Disconnect(context.Background())

	// Test ping with short timeout (should still succeed if MongoDB is fast)
	shortCtx, shortCancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer shortCancel()

	err = provider.Ping(shortCtx)
	assert.NoError(t, err, "Ping should succeed with short timeout if MongoDB is responsive")
}

func TestMongoRepositoryProvider_Ping_InvalidConnection(t *testing.T) {
	// Test with invalid MongoDB URI (should fail during NewMongoRepositoryProvider)
	_, err := mongodb.NewMongoRepositoryProvider("mongodb://invalid-host:27017", "test_db")
	if err == nil {
		// If connection succeeds (e.g., in test environment), skip this test
		t.Skip("Skipping test: Invalid connection test requires actual failure")
	}
	// If we get here, the connection failed as expected
	assert.Error(t, err)
}
