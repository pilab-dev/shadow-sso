package mongodb

import (
	"context"
	"errors"
	"time"

	"github.com/pilab-dev/shadow-sso/domain"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

// PARCollection is the collection holding pushed authorization requests.
const PARCollection = "pushed_authorization_requests"

// MongoPARStore implements domain.PARStore with a TTL index on expires_at.
type MongoPARStore struct {
	collection *mongo.Collection
}

type parDoc struct {
	ID        string            `bson:"_id"`
	ClientID  string            `bson:"client_id"`
	Params    map[string]string `bson:"params"`
	ExpiresAt time.Time         `bson:"expires_at"`
}

func NewPARStore(ctx context.Context, db *mongo.Database) (*MongoPARStore, error) {
	c := db.Collection(PARCollection)
	_, err := c.Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys:    bson.D{{Key: "expires_at", Value: 1}},
		Options: options.Index().SetExpireAfterSeconds(0),
	})
	if err != nil {
		return nil, err
	}
	return &MongoPARStore{collection: c}, nil
}

func (s *MongoPARStore) Put(ctx context.Context, uri, clientID string, params map[string]string, ttl time.Duration) error {
	_, err := s.collection.InsertOne(ctx, parDoc{ID: uri, ClientID: clientID, Params: params, ExpiresAt: time.Now().Add(ttl)})
	return err
}

func (s *MongoPARStore) Consume(ctx context.Context, uri, clientID string) (map[string]string, error) {
	var doc parDoc
	err := s.collection.FindOneAndDelete(ctx, bson.M{"_id": uri}).Decode(&doc)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return nil, domain.ErrPARNotFound
	}
	if err != nil {
		return nil, err
	}
	// The TTL monitor runs only periodically, so enforce expiry on read too.
	if time.Now().After(doc.ExpiresAt) || doc.ClientID != clientID {
		return nil, domain.ErrPARNotFound
	}
	return doc.Params, nil
}
