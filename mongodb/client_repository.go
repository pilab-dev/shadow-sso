package mongodb

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/pilab-dev/shadow-sso/domain"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
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
func NewClientRepository(_ context.Context, db *mongo.Database) *ClientRepository {
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
	result, err := s.coll.ReplaceOne(ctx, filter, c)
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

// clientSortFields maps the sort keys accepted by ClientFilter.SortBy to the
// underlying MongoDB field names. Only these keys are honored; buildClientSort
// silently falls back to the default client_id asc ordering for anything else.
var clientSortFields = map[string]string{
	"clientId":   "client_id",
	"clientName": "client_name",
}

// ListClientsPage implements the ClientStore interface.
func (s *ClientRepository) ListClientsPage(ctx context.Context, filter domain.ClientFilter, skip, limit int) ([]*domain.Client, int64, error) {
	if limit <= 0 || limit > 500 {
		limit = 50
	}
	if skip < 0 {
		skip = 0
	}

	mongoFilter := s.buildClientFilter(filter)

	total, err := s.coll.CountDocuments(ctx, mongoFilter)
	if err != nil {
		return nil, 0, err
	}

	findOpts := options.Find().
		SetSort(s.buildClientSort(filter)).
		SetSkip(int64(skip)).
		SetLimit(int64(limit))

	cursor, err := s.coll.Find(ctx, mongoFilter, findOpts)
	if err != nil {
		return nil, 0, err
	}
	defer cursor.Close(ctx)

	var clients []*domain.Client
	if err := cursor.All(ctx, &clients); err != nil {
		return nil, 0, err
	}

	return clients, total, nil
}

// buildClientFilter translates ClientFilter into a MongoDB filter document,
// honoring every field. Enabled maps to is_active and PublicClient maps to
// client_type == "public", matching how the GraphQL resolvers derive the
// enabled/publicClient Client fields from the domain model.
func (s *ClientRepository) buildClientFilter(filter domain.ClientFilter) bson.M {
	mongoFilter := bson.M{}
	if filter.Type != "" {
		mongoFilter["client_type"] = filter.Type
	}
	if filter.IsActive {
		mongoFilter["is_active"] = true
	}
	if filter.ClientID != "" {
		mongoFilter["client_id"] = filter.ClientID
	}
	if filter.ClientName != "" {
		mongoFilter["client_name"] = bson.M{"$regex": regexp.QuoteMeta(filter.ClientName), "$options": "i"}
	}
	if filter.Enabled != nil {
		mongoFilter["is_active"] = *filter.Enabled
	}
	if filter.PublicClient != nil {
		if *filter.PublicClient {
			mongoFilter["client_type"] = domain.ClientTypePublic
		} else {
			mongoFilter["client_type"] = bson.M{"$ne": domain.ClientTypePublic}
		}
	}
	if filter.Search != "" {
		escaped := regexp.QuoteMeta(filter.Search)
		mongoFilter["$or"] = []bson.M{
			{"client_id": bson.M{"$regex": escaped, "$options": "i"}},
			{"client_name": bson.M{"$regex": escaped, "$options": "i"}},
			{"description": bson.M{"$regex": escaped, "$options": "i"}},
		}
	}
	return mongoFilter
}

// buildClientSort translates ClientFilter.SortBy/SortDir into a MongoDB sort
// document. Only the allowlisted keys in clientSortFields are honored; an
// empty or unknown SortBy falls back to client_id asc so paging stays stable.
// SortDir accepts "asc"/"desc" and defaults to asc for known fields.
func (s *ClientRepository) buildClientSort(filter domain.ClientFilter) bson.D {
	field, ok := clientSortFields[filter.SortBy]
	if !ok {
		return bson.D{{Key: "client_id", Value: 1}}
	}
	dir := 1
	if strings.ToLower(filter.SortDir) == "desc" {
		dir = -1
	}
	return bson.D{{Key: field, Value: dir}}
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
