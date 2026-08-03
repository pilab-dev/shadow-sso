package integration

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"testing"
	"time"

	ssso "github.com/pilab-dev/shadow-sso"
	"github.com/pilab-dev/shadow-sso/apps/ssso/config"
	"github.com/pilab-dev/shadow-sso/apps/ssso/server"
	"github.com/pilab-dev/shadow-sso/mongodb"
	"github.com/pilab-dev/shadow-sso/services"
)

// TestConfig returns a config.Config suitable for integration tests.
// It uses a random port (via HTTPAddr: "127.0.0.1:0") and MONGO_TEST_URI.
func TestConfig(dbName string) config.Config {
	mongoURI := os.Getenv("MONGO_TEST_URI")
	if mongoURI == "" {
		mongoURI = "mongodb://localhost:27017"
	}
	return config.Config{
		HTTPAddr:             "127.0.0.1:0",
		MgmtHTTPAddr:         "127.0.0.1:0",
		LogLevel:             "fatal",
		MongoURI:             mongoURI,
		MongoDBName:          dbName,
		IssuerURL:            "http://localhost:8080",
		TokenSigningKey:      "test-signing-key-for-integration-tests-at-least-32-chars!",
		ConfigEncryptionKey:  "test-encryption-key-32bytes!!!!!",
		TokenCacheDefaultTTL: 5 * time.Minute,
		KeyRotationInterval:  1 * time.Hour,
		JSONLog:              false,
		AllowedOrigins:       []string{"*"},
	}
}

// StartTestServer starts an SSO server for testing.
// It creates a unique MongoDB database, starts the server on a random port,
// and returns the server, repository provider, and the address the server is listening on.
// Call StopTestServer to clean up.
func StartTestServer(t testing.TB, extraCfg ...func(*config.Config)) (*http.Server, services.RepositoryProvider, string) {
	t.Helper()

	// Create unique DB name for test isolation
	dbName := "test_sso_int_" + strconv.FormatInt(time.Now().UnixNano(), 10)

	cfg := TestConfig(dbName)

	// Apply any extra config overrides
	for _, fn := range extraCfg {
		fn(&cfg)
	}

	// Connect to MongoDB
	mongoURI := os.Getenv("MONGO_TEST_URI")
	if mongoURI == "" {
		mongoURI = "mongodb://localhost:27017"
	}

	repoProvider, err := ssso.NewMongoRepositoryProvider(mongoURI, dbName)
	if err != nil {
		t.Skipf("MongoDB not available: %v", err)
		return nil, nil, ""
	}

	// Bootstrap default configurations (required for server to function)
	bCtx := context.Background()
	configRepo := repoProvider.ConfigurationRepository(bCtx)
	if err := configRepo.CreateDefaultConfigs(bCtx); err != nil {
		// Non-fatal; server works without defaults but some features may be unavailable
		t.Logf("Warning: Failed to bootstrap default configs: %v", err)
	}

	// Start the SSO server
	srv, err := server.StartServer(bCtx, cfg, repoProvider)
	if err != nil {
		// Cleanup on failure
		if mongoRp, ok := repoProvider.(*mongodb.MongoRepositoryProvider); ok {
			_ = mongoRp.Disconnect(bCtx)
		}
		t.Fatalf("Failed to start test server: %v", err)
		return nil, nil, ""
	}

	// srv.Addr is the actual listening address set by StartServer via net.Listen
	addr := fmt.Sprintf("http://%s", srv.Addr)

	return srv, repoProvider, addr
}

// StopTestServer stops the test server and cleans up the MongoDB database.
func StopTestServer(t testing.TB, srv *http.Server, provider services.RepositoryProvider) {
	t.Helper()

	// Shutdown HTTP server
	if srv != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := srv.Shutdown(ctx); err != nil {
			t.Logf("Warning: Failed to shut down test server: %v", err)
		}
	}

	// Disconnect from MongoDB
	if provider != nil {
		if mongoRp, ok := provider.(*mongodb.MongoRepositoryProvider); ok {
			if err := mongoRp.Disconnect(context.Background()); err != nil {
				t.Logf("Warning: Failed to disconnect from MongoDB: %v", err)
			}
		}
	}
}
