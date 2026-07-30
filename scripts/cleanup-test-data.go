//go:build ignore

package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/joho/godotenv"
	"github.com/rs/zerolog/log"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

func main() {
	godotenv.Load("../.env")
	
	uri := os.Getenv("SSSO_MONGO_URI")
	dbName := os.Getenv("SSSO_MONGO_DB_NAME")
	
	log.Info().Str("db", dbName).Msg("Connecting to MongoDB")
	
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	
	client, _ := mongo.Connect(options.Client().ApplyURI(uri))
	client.Ping(ctx, nil)
	db := client.Database(dbName)
	
	totalDeleted := int64(0)
	
	// 1. Remove test user (admin@example.com)
	fmt.Println("\n--- Removing test users ---")
	result, _ := db.Collection("oauth_users").DeleteOne(ctx, bson.M{"email": "admin@example.com"})
	if result.DeletedCount > 0 {
		fmt.Printf("✓ Removed test user: admin@example.com\n")
		totalDeleted += result.DeletedCount
	}
	
	// 2. Remove duplicate test-app clients (keep only one)
	fmt.Println("\n--- Removing duplicate test clients ---")
	
	// First, count how many test-app clients exist
	count, _ := db.Collection("oauth_clients").CountDocuments(ctx, bson.M{"client_id": "test-app"})
	fmt.Printf("  Found %d duplicate test-app clients\n", count)
	
	if count > 1 {
		// Get all test-app client IDs
		cursor, _ := db.Collection("oauth_clients").Find(ctx, bson.M{"client_id": "test-app"})
		var testClients []bson.M
		cursor.All(ctx, &testClients)
		
		// Keep the first one, delete the rest
		var deleteIDs []bson.M
		for i := 1; i < len(testClients); i++ {
			deleteIDs = append(deleteIDs, bson.M{"_id": testClients[i]["_id"]})
		}
		
		if len(deleteIDs) > 0 {
			result, _ = db.Collection("oauth_clients").DeleteMany(ctx, bson.M{"$or": deleteIDs})
			fmt.Printf("✓ Removed %d duplicate test-app clients (kept one)\n", result.DeletedCount)
			totalDeleted += result.DeletedCount
		}
	}
	
	// 3. Remove test-app related tokens (if any)
	fmt.Println("\n--- Removing test-app tokens ---")
	result, _ = db.Collection("oauth_tokens").DeleteMany(ctx, bson.M{"client_id": "test-app"})
	if result.DeletedCount > 0 {
		fmt.Printf("✓ Removed %d test-app tokens\n", result.DeletedCount)
		totalDeleted += result.DeletedCount
	}
	
	// 4. Remove test-app related auth codes (if any)
	fmt.Println("\n--- Removing test-app auth codes ---")
	result, _ = db.Collection("oauth_auth_codes").DeleteMany(ctx, bson.M{"client_id": "test-app"})
	if result.DeletedCount > 0 {
		fmt.Printf("✓ Removed %d test-app auth codes\n", result.DeletedCount)
		totalDeleted += result.DeletedCount
	}
	
	// 5. Remove test-app related sessions (if any)
	fmt.Println("\n--- Removing test-app sessions ---")
	result, _ = db.Collection("oauth_user_sessions").DeleteMany(ctx, bson.M{"client_id": "test-app"})
	if result.DeletedCount > 0 {
		fmt.Printf("✓ Removed %d test-app sessions\n", result.DeletedCount)
		totalDeleted += result.DeletedCount
	}
	
	// 6. Remove test-app related PKCE challenges (if any)
	fmt.Println("\n--- Removing test-app PKCE challenges ---")
	result, _ = db.Collection("pkce_challenges").DeleteMany(ctx, bson.M{"client_id": "test-app"})
	if result.DeletedCount > 0 {
		fmt.Printf("✓ Removed %d test-app PKCE challenges\n", result.DeletedCount)
		totalDeleted += result.DeletedCount
	}
	
	// 7. Remove test-app related device authorizations (if any)
	fmt.Println("\n--- Removing test-app device authorizations ---")
	result, _ = db.Collection("device_authorizations").DeleteMany(ctx, bson.M{"client_id": "test-app"})
	if result.DeletedCount > 0 {
		fmt.Printf("✓ Removed %d test-app device authorizations\n", result.DeletedCount)
		totalDeleted += result.DeletedCount
	}
	
	// Summary
	fmt.Println("\n========================================")
	fmt.Println("  Test Data Cleanup Summary")
	fmt.Println("========================================")
	fmt.Printf("Total documents removed: %d\n", totalDeleted)
	fmt.Println("========================================")
	
	fmt.Println("\nRemaining data:")
	cursor, _ := db.Collection("oauth_users").Find(ctx, bson.M{})
	var users []bson.M
	cursor.All(ctx, &users)
	fmt.Println("  Users:")
	for _, u := range users {
		fmt.Printf("    - %s (%s)\n", u["email"], u["_id"])
	}
	
	cursor, _ = db.Collection("oauth_clients").Find(ctx, bson.M{})
	var clients []bson.M
	cursor.All(ctx, &clients)
	fmt.Println("  Clients:")
	for _, c := range clients {
		fmt.Printf("    - %s (%s)\n", c["client_name"], c["client_id"])
	}
}
