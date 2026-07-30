//go:build ignore

package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/joho/godotenv"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

func main() {
	godotenv.Load("../.env")
	
	uri := os.Getenv("SSSO_MONGO_URI")
	dbName := os.Getenv("SSSO_MONGO_DB_NAME")
	
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	
	client, _ := mongo.Connect(options.Client().ApplyURI(uri))
	client.Ping(ctx, nil)
	db := client.Database(dbName)
	
	totalDeleted := int64(0)
	
	testClients := []string{"test-app", "confidential-app", "spa-app"}
	
	for _, clientID := range testClients {
		fmt.Printf("\n--- Removing %s ---\n", clientID)
		
		// Remove client
		result, _ := db.Collection("oauth_clients").DeleteOne(ctx, bson.M{"client_id": clientID})
		if result.DeletedCount > 0 {
			fmt.Printf("  ✓ Removed client\n")
			totalDeleted += result.DeletedCount
		}
		
		// Remove associated tokens
		result, _ = db.Collection("oauth_tokens").DeleteMany(ctx, bson.M{"client_id": clientID})
		if result.DeletedCount > 0 {
			fmt.Printf("  ✓ Removed %d tokens\n", result.DeletedCount)
			totalDeleted += result.DeletedCount
		}
		
		// Remove associated auth codes
		result, _ = db.Collection("oauth_auth_codes").DeleteMany(ctx, bson.M{"client_id": clientID})
		if result.DeletedCount > 0 {
			fmt.Printf("  ✓ Removed %d auth codes\n", result.DeletedCount)
			totalDeleted += result.DeletedCount
		}
		
		// Remove associated sessions
		result, _ = db.Collection("oauth_user_sessions").DeleteMany(ctx, bson.M{"client_id": clientID})
		if result.DeletedCount > 0 {
			fmt.Printf("  ✓ Removed %d sessions\n", result.DeletedCount)
			totalDeleted += result.DeletedCount
		}
		
		// Remove associated PKCE challenges
		result, _ = db.Collection("pkce_challenges").DeleteMany(ctx, bson.M{"client_id": clientID})
		if result.DeletedCount > 0 {
			fmt.Printf("  ✓ Removed %d PKCE challenges\n", result.DeletedCount)
			totalDeleted += result.DeletedCount
		}
		
		// Remove associated device authorizations
		result, _ = db.Collection("device_authorizations").DeleteMany(ctx, bson.M{"client_id": clientID})
		if result.DeletedCount > 0 {
			fmt.Printf("  ✓ Removed %d device authorizations\n", result.DeletedCount)
			totalDeleted += result.DeletedCount
		}
	}
	
	fmt.Println("\n========================================")
	fmt.Printf("Total documents removed: %d\n", totalDeleted)
	fmt.Println("========================================")
	
	// Show remaining clients
	fmt.Println("\nRemaining clients:")
	cursor, _ := db.Collection("oauth_clients").Find(ctx, bson.M{})
	var clients []bson.M
	cursor.All(ctx, &clients)
	if len(clients) == 0 {
		fmt.Println("  (none)")
	}
	for _, c := range clients {
		fmt.Printf("  - %s (%s)\n", c["client_name"], c["client_id"])
	}
}
