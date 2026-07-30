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
	
	// 1. Remove stale "Frontend BFF" client from clients collection
	fmt.Println("--- Removing stale Frontend BFF client ---")
	result, _ := db.Collection("clients").DeleteOne(ctx, bson.M{"client_id": "frontend-bff"})
	if result.DeletedCount > 0 {
		fmt.Printf("  ✓ Removed Frontend BFF\n")
		totalDeleted += result.DeletedCount
	}
	
	// 2. Remove all test clients from oauth_clients collection
	fmt.Println("\n--- Removing test clients from oauth_clients ---")
	testClients := []string{"test-app", "confidential-app", "spa-app"}
	for _, clientID := range testClients {
		result, _ = db.Collection("oauth_clients").DeleteOne(ctx, bson.M{"client_id": clientID})
		if result.DeletedCount > 0 {
			fmt.Printf("  ✓ Removed %s\n", clientID)
			totalDeleted += result.DeletedCount
		}
	}
	
	// 3. Drop the empty "users" collection (orphan - code uses "oauth_users")
	fmt.Println("\n--- Dropping orphan 'users' collection ---")
	err := db.Collection("users").Drop(ctx)
	if err != nil {
		fmt.Printf("  ⚠ Could not drop: %v\n", err)
	} else {
		fmt.Printf("  ✓ Dropped 'users' collection\n")
	}
	
	// Summary
	fmt.Println("\n========================================")
	fmt.Printf("Total documents removed: %d\n", totalDeleted)
	fmt.Println("========================================")
	
	// Show remaining clients
	fmt.Println("\nRemaining clients in 'clients' collection:")
	cursor, _ := db.Collection("clients").Find(ctx, bson.M{})
	var docs []bson.M
	cursor.All(ctx, &docs)
	for _, d := range docs {
		fmt.Printf("  - %s: %s\n", d["client_id"], d["client_name"])
	}
	
	fmt.Println("\nRemaining clients in 'oauth_clients' collection:")
	cursor, _ = db.Collection("oauth_clients").Find(ctx, bson.M{})
	docs = nil
	cursor.All(ctx, &docs)
	if len(docs) == 0 {
		fmt.Println("  (empty)")
	}
	for _, d := range docs {
		fmt.Printf("  - %s: %s\n", d["client_id"], d["client_name"])
	}
}
