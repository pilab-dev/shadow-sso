package mongodb

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/pilab-dev/shadow-sso/domain"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"golang.org/x/crypto/bcrypt"
)

var (
	ErrInvalidClientCredentials = errors.New("invalid client credentials")
	ErrClientNotFound           = errors.New("client not found")
)

// ClientRepository implements the ClientStore interface using MongoDB.
type ClientRepository struct {
	coll *mongo.Collection
}

// NewClientRepository creates a new MongoStore instance.
func NewClientRepository(db *mongo.Database) *ClientRepository {
	return &ClientRepository{
		coll: db.Collection("clients"),
	}
}

// CreateClient implements the ClientStore interface.
func (s *ClientRepository) CreateClient(ctx context.Context, c *domain.Client) error {
	c.CreatedAt = time.Now()
	c.UpdatedAt = time.Now()

	_, err := s.coll.InsertOne(ctx, c)
	return err
}

// GetClient implements the ClientStore interface.
func (s *ClientRepository) GetClient(ctx context.Context, clientID string) (*domain.Client, error) {
	filter := bson.M{"client_id": clientID}
	var cli domain.Client

	err := s.coll.FindOne(ctx, filter).Decode(&cli)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, ErrClientNotFound
		}
		return nil, err
	}

	return &cli, nil
}

// UpdateClient implements the ClientStore interface.
func (s *ClientRepository) UpdateClient(ctx context.Context, c *domain.Client) error {
	c.UpdatedAt = time.Now()

	filter := bson.M{"client_id": c.ID}
	update := bson.M{"$set": c}
	result, err := s.coll.ReplaceOne(ctx, filter, update)
	if err != nil {
		return err
	}
	if result.MatchedCount == 0 {
		return fmt.Errorf("update failed: %w", ErrClientNotFound)
	}
	return nil
}

// DeleteClient implements the ClientStore interface.
func (s *ClientRepository) DeleteClient(ctx context.Context, clientID string) error {
	filter := bson.M{"client_id": clientID}
	result, err := s.coll.DeleteOne(ctx, filter)
	if err != nil {
		return err
	}
	if result.DeletedCount == 0 {
		return fmt.Errorf("delete failed: %w", ErrClientNotFound)
	}
	return nil
}

// ListClients implements the ClientStore interface.
func (s *ClientRepository) ListClients(ctx context.Context, filter domain.ClientFilter) ([]*domain.Client, error) {
	mongoFilter := bson.M{}
	if filter.Type != "" {
		mongoFilter["client_type"] = filter.Type
	}
	if filter.IsActive {
		mongoFilter["is_active"] = true
	}
	if filter.Search != "" {
		escaped := regexp.QuoteMeta(filter.Search)
		mongoFilter["$or"] = []bson.M{
			{"client_id": bson.M{"$regex": escaped, "$options": "i"}},
			{"client_name": bson.M{"$regex": escaped, "$options": "i"}},
			{"description": bson.M{"$regex": escaped, "$options": "i"}},
		}
	}

	cursor, err := s.coll.Find(ctx, mongoFilter)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var clients []*domain.Client
	if err := cursor.All(ctx, &clients); err != nil {
		return nil, err
	}

	return clients, nil
}

// ValidateClient implements domain.ClientRepository.
func (s *ClientRepository) ValidateClient(ctx context.Context, clientID string, clientSecret string) (*domain.Client, error) {
	filter := bson.M{"client_id": clientID}
	var cli domain.Client

	err := s.coll.FindOne(ctx, filter).Decode(&cli)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, ErrClientNotFound
		}

		return nil, err
	}

	// For public clients, the secret is not checked
	if cli.Type == domain.ClientTypePublic {
		return &cli, nil
	}

	// For confidential clients, verify the secret against stored bcrypt hash
	if err := bcrypt.CompareHashAndPassword([]byte(cli.Secret), []byte(clientSecret)); err == nil {
		return &cli, nil
	}

	return nil, ErrInvalidClientCredentials
}
