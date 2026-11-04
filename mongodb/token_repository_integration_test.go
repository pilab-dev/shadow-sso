package mongodb_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/pilab-dev/shadow-sso/domain"
	"github.com/pilab-dev/shadow-sso/mongodb"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

func TestTokenRepository_HashesRefreshTokenAtRest(t *testing.T) {
	mongoURI := os.Getenv("MONGO_TEST_URI")
	if mongoURI == "" {
		mongoURI = "mongodb://localhost:27017"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	client, err := mongo.Connect(options.Client().ApplyURI(mongoURI).SetConnectTimeout(2 * time.Second))
	if err != nil {
		t.Skipf("MongoDB not available: %v", err)
	}
	if err := client.Ping(ctx, nil); err != nil {
		t.Skipf("MongoDB not available: %v", err)
	}
	dbName := fmt.Sprintf("test_sso_token_hash_%d", time.Now().UnixNano())
	db := client.Database(dbName)
	defer func() { _ = db.Drop(context.Background()); _ = client.Disconnect(context.Background()) }()

	repo := mongodb.NewTokenRepository(ctx, db)
	raw := "raw-refresh-token-value"
	tok := &domain.Token{
		ID: "refresh-1", TokenType: domain.TokenTypeRefreshToken, TokenValue: raw,
		UserID: "user-1", ClientID: "client-1", ExpiresAt: time.Now().Add(time.Hour), CreatedAt: time.Now(),
	}
	if err := repo.StoreToken(ctx, tok); err != nil {
		t.Fatal(err)
	}

	var stored domain.Token
	if err := db.Collection(mongodb.TokensCollection).FindOne(ctx, bson.M{"_id": "refresh-1"}).Decode(&stored); err != nil {
		t.Fatal(err)
	}
	if stored.TokenValue != "" {
		t.Fatalf("raw refresh token persisted: %q", stored.TokenValue)
	}
	sum := sha256.Sum256([]byte(raw))
	want := hex.EncodeToString(sum[:])
	if stored.TokenHash != want {
		t.Fatalf("hash mismatch: got %q want %q", stored.TokenHash, want)
	}
	if _, err := repo.GetRefreshTokenInfo(ctx, raw); err != nil {
		t.Fatalf("lookup by raw token failed: %v", err)
	}
}
