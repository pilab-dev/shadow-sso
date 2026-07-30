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
	
	// Check orphan collections
	orphanCollections := []string{"clients", "users"}
	
	for _, collName := range orphanCollections {
		fmt.Printf("\n=== %s ===\n", collName)
		count, _ := db.Collection(collName).CountDocuments(ctx, bson.M{})
		fmt.Printf("  Documents: %d\n", count)
		
		if count > 0 {
			cursor, _ := db.Collection(collName).Find(ctx, bson.M{}, options.Find().SetLimit(5))
			var docs []bson.M
			cursor.All(ctx, &docs)
			for i, doc := range docs {
				fmt.Printf("  [%d] %v\n", i+1, doc)
			}
		}
	}
	
	// Also check pkce_challenges vs oauth_pkce_challenges
	fmt.Println("\n=== pkce_challenges ===")
	count, _ := db.Collection("pkce_challenges").CountDocuments(ctx, bson.M{})
	fmt.Printf("  Documents: %d\n", count)
	
	fmt.Println("\n=== oauth_pkce_challenges ===")
	count, _ = db.Collection("oauth_pkce_challenges").CountDocuments(ctx, bson.M{})
	fmt.Printf("  Documents: %d\n", count)
}
