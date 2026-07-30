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
	
	// List all collections
	collections, _ := db.ListCollectionNames(ctx, bson.M{})
	fmt.Println("Collections:", collections)
	
	// Show users
	fmt.Println("\n=== USERS ===")
	cursor, _ := db.Collection("oauth_users").Find(ctx, bson.M{})
	var users []bson.M
	cursor.All(ctx, &users)
	for _, u := range users {
		fmt.Printf("  ID: %v, Email: %v, Name: %v %v\n", u["_id"], u["email"], u["first_name"], u["last_name"])
	}
	
	// Show clients
	fmt.Println("\n=== CLIENTS ===")
	cursor, _ = db.Collection("oauth_clients").Find(ctx, bson.M{})
	var clients []bson.M
	cursor.All(ctx, &clients)
	for _, c := range clients {
		fmt.Printf("  ID: %v, Name: %v, Type: %v\n", c["client_id"], c["client_name"], c["client_type"])
	}
	
	// Show service accounts
	fmt.Println("\n=== SERVICE ACCOUNTS ===")
	cursor, _ = db.Collection("service_accounts").Find(ctx, bson.M{})
	var sas []bson.M
	cursor.All(ctx, &sas)
	for _, sa := range sas {
		fmt.Printf("  ID: %v, Email: %v, Name: %v\n", sa["_id"], sa["client_email"], sa["display_name"])
	}
	
	// Show groups
	fmt.Println("\n=== GROUPS ===")
	cursor, _ = db.Collection("realm_groups").Find(ctx, bson.M{})
	var groups []bson.M
	cursor.All(ctx, &groups)
	for _, g := range groups {
		fmt.Printf("  ID: %v, Name: %v\n", g["_id"], g["name"])
	}
	
	// Show identity providers
	fmt.Println("\n=== IDENTITY PROVIDERS ===")
	cursor, _ = db.Collection("identity_providers").Find(ctx, bson.M{})
	var idps []bson.M
	cursor.All(ctx, &idps)
	for _, idp := range idps {
		fmt.Printf("  ID: %v, Name: %v, Type: %v\n", idp["_id"], idp["name"], idp["type"])
	}
	
	// Show token counts
	fmt.Println("\n=== TOKEN COUNTS ===")
	count, _ := db.Collection("oauth_tokens").CountDocuments(ctx, bson.M{})
	fmt.Printf("  Total tokens: %d\n", count)
	
	// Show session counts
	fmt.Println("\n=== SESSION COUNTS ===")
	count, _ = db.Collection("oauth_user_sessions").CountDocuments(ctx, bson.M{})
	fmt.Printf("  OAuth sessions: %d\n", count)
	count, _ = db.Collection("user_sessions_oidc").CountDocuments(ctx, bson.M{})
	fmt.Printf("  OIDC sessions: %d\n", count)
}
