package testutil

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

// SetupTestMongoDB sets up a new MongoDB database for testing.
// It returns a pointer to the database and a cleanup function.
// The cleanup function drops the database and disconnects the client.
func SetupTestMongoDB(t *testing.T, dbNamePrefix string) (*mongo.Database, func()) {
	t.Helper()

	mongoURI := os.Getenv("TEST_MONGO_URI")
	if mongoURI == "" {
		mongoURI = "mongodb://localhost:27017"
	}

	// For CI environments, often a different URI is needed.
	// Example: "mongodb://mongodb:27017" if running in Docker Compose network.
	// This logic might need adjustment based on specific CI setup.
	if os.Getenv("CI") != "" && os.Getenv("TEST_MONGO_URI_CI") != "" {
		mongoURI = os.Getenv("TEST_MONGO_URI_CI")
	}

	dbName := fmt.Sprintf("%s_%d", dbNamePrefix, time.Now().UnixNano())

	clientOpts := options.Client().ApplyURI(mongoURI)
	// It's good practice to set a server selection timeout.
	// If the server is not available, connection attempts will time out after this duration.
	serverAPIOptions := options.ServerAPI(options.ServerAPIVersion1)
	clientOpts.SetServerAPIOptions(serverAPIOptions)       // Recommended for new applications
	clientOpts.SetServerSelectionTimeout(10 * time.Second) // Example timeout

	client, err := mongo.Connect(clientOpts)
	if err != nil {
		t.Fatalf("Failed to create MongoDB client: %v (URI: %s)", err, mongoURI)
	}

	// Ping the primary to verify that the client can connect to the deployment.
	// Using a context with timeout for the ping operation.
	pingCtx, cancelPing := context.WithTimeout(context.Background(), 5*time.Second) // Short timeout for ping
	defer cancelPing()
	if err = client.Ping(pingCtx, nil); err != nil {
		// Disconnect client if ping fails, as it's unusable.
		disconnectCtx, cancelDisconnect := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancelDisconnect()
		client.Disconnect(disconnectCtx)
		t.Fatalf("Failed to connect to MongoDB (ping failed): %v (URI: %s)", err, mongoURI)
	}

	db := client.Database(dbName)

	cleanup := func() {
		dropCtx, cancelDrop := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancelDrop()
		if err := db.Drop(dropCtx); err != nil {
			t.Logf("Warning: Failed to drop database %s: %v", dbName, err)
		}

		disconnectCtx, cancelDisconnect := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancelDisconnect()
		if err := client.Disconnect(disconnectCtx); err != nil {
			t.Logf("Warning: Failed to disconnect MongoDB client: %v", err)
		}
	}

	return db, cleanup
}
