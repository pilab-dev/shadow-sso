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
	
	// Compare clients vs oauth_clients
	fmt.Println("=== clients collection ===")
	count, _ := db.Collection("clients").CountDocuments(ctx, bson.M{})
	fmt.Printf("  Count: %d\n", count)
	cursor, _ := db.Collection("clients").Find(ctx, bson.M{}, options.Find().SetProjection(bson.M{"client_id": 1, "client_name": 1}).SetLimit(10))
	var docs []bson.M
	cursor.All(ctx, &docs)
	for _, d := range docs {
		fmt.Printf("  - %s: %s\n", d["client_id"], d["client_name"])
	}
	
	fmt.Println("\n=== oauth_clients collection ===")
	count, _ = db.Collection("oauth_clients").CountDocuments(ctx, bson.M{})
	fmt.Printf("  Count: %d\n", count)
	cursor, _ = db.Collection("oauth_clients").Find(ctx, bson.M{}, options.Find().SetProjection(bson.M{"client_id": 1, "client_name": 1}).SetLimit(10))
	docs = nil
	cursor.All(ctx, &docs)
	for _, d := range docs {
		fmt.Printf("  - %s: %s\n", d["client_id"], d["client_name"])
	}
}
