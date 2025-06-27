package mongodb

import (
	"context"
	"errors"
	"time"

	"github.com/pilab-dev/shadow-sso/domain"
	"github.com/rs/zerolog/log"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

// IdPRepositoryMongo implements the domain.IdPRepository interface using MongoDB.
type IdPRepositoryMongo struct {
	collection *mongo.Collection
}

// NewIdPRepositoryMongo creates a new IdPRepositoryMongo.
// It also ensures that necessary indexes are created on the collection.
func NewIdPRepositoryMongo(ctx context.Context, db *mongo.Database) (domain.IdPRepository, error) {
	repo := &IdPRepositoryMongo{
		collection: db.Collection(IdPsCollection),
	}

	indexModels := []mongo.IndexModel{
		{
			Keys:    bson.D{{Key: "_id", Value: 1}}, // IdP Configuration ID
			Options: options.Index().SetUnique(true),
		},
		{
			Keys:    bson.D{{Key: "name", Value: 1}}, // IdP Name should be unique
			Options: options.Index().SetUnique(true),
		},
		{
			Keys:    bson.D{{Key: "type", Value: 1}}, // To query by IdP type (OIDC, SAML)
			Options: options.Index(),
		},
		{
			Keys:    bson.D{{Key: "is_enabled", Value: 1}}, // To query enabled IdPs
			Options: options.Index(),
		},
	}

	timeoutCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	_, err := repo.collection.Indexes().CreateMany(timeoutCtx, indexModels)
	if err != nil {
		log.Warn().Err(err).Msg("Issue creating indexes for identity_providers collection (might already exist or other error)")
		// Consider returning the error if index creation is critical for startup:
		// return nil, fmt.Errorf("failed to create IdP indexes: %w", err)
	} else {
		log.Info().Msg("Indexes for identity_providers collection ensured.")
	}
	return repo, nil
}

// AddIdP stores a new IdP configuration.
func (r *IdPRepositoryMongo) AddIdP(ctx context.Context, idp *domain.IdentityProvider) error {
	if idp.ID == "" {
		idp.ID = NewObjectID() // From mongodb/utils.go
	}
	if idp.CreatedAt.IsZero() {
		idp.CreatedAt = time.Now().UTC()
	}
	idp.UpdatedAt = time.Now().UTC()

	_, err := r.collection.InsertOne(ctx, idp)
	if err != nil {
		if mongo.IsDuplicateKeyError(err) { // Handles duplicate _id or name
			return errors.New("IdP with this ID or Name already exists")
		}
		log.Error().Err(err).Msg("Error adding IdP configuration to MongoDB")
		return err
	}
	return nil
}

// GetIdPByID retrieves an IdP configuration by its ID.
func (r *IdPRepositoryMongo) GetIdPByID(ctx context.Context, id string) (*domain.IdentityProvider, error) {
	var idp domain.IdentityProvider
	err := r.collection.FindOne(ctx, bson.M{"_id": id}).Decode(&idp)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, errors.New("identity provider not found by ID")
		}
		log.Error().Err(err).Str("idpID", id).Msg("Error retrieving IdP by ID from MongoDB")
		return nil, err
	}
	return &idp, nil
}

// GetIdPByName retrieves an IdP configuration by its unique Name.
func (r *IdPRepositoryMongo) GetIdPByName(ctx context.Context, name string) (*domain.IdentityProvider, error) {
	var idp domain.IdentityProvider
	err := r.collection.FindOne(ctx, bson.M{"name": name}).Decode(&idp)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, errors.New("identity provider not found by Name")
		}
		log.Error().Err(err).Str("idpName", name).Msg("Error retrieving IdP by Name from MongoDB")
		return nil, err
	}
	return &idp, nil
}

// ListIdPs retrieves a list of IdP configurations, optionally filtering by enabled status.
func (r *IdPRepositoryMongo) ListIdPs(ctx context.Context, onlyEnabled bool) ([]*domain.IdentityProvider, error) {
	filter := bson.M{}
	if onlyEnabled {
		filter["is_enabled"] = true
	}

	findOptions := options.Find().SetSort(bson.D{{"name", 1}})

	cursor, err := r.collection.Find(ctx, filter, findOptions)
	if err != nil {
		log.Error().Err(err).Msg("Error listing IdP configurations from MongoDB")
		return nil, err
	}
	defer cursor.Close(ctx)

	var idps []*domain.IdentityProvider
	if err = cursor.All(ctx, &idps); err != nil {
		log.Error().Err(err).Msg("Error decoding listed IdP configurations from MongoDB")
		return nil, err
	}
	return idps, nil
}

// UpdateIdP updates an existing IdP configuration.
func (r *IdPRepositoryMongo) UpdateIdP(ctx context.Context, idp *domain.IdentityProvider) error {
	if idp.ID == "" {
		return errors.New("IdP configuration ID cannot be empty for update")
	}
	filter := bson.M{"_id": idp.ID}
	idp.UpdatedAt = time.Now().UTC()

	result, err := r.collection.ReplaceOne(ctx, filter, idp)
	if err != nil {
		if mongo.IsDuplicateKeyError(err) { // Handles duplicate name if name is changed to an existing one
			return errors.New("IdP with this Name already exists")
		}
		log.Error().Err(err).Str("idpID", idp.ID).Msg("Error updating IdP configuration in MongoDB")
		return err
	}
	if result.MatchedCount == 0 {
		return errors.New("IdP configuration not found for update")
	}
	return nil
}

// DeleteIdP removes an IdP configuration by its ID.
func (r *IdPRepositoryMongo) DeleteIdP(ctx context.Context, id string) error {
	result, err := r.collection.DeleteOne(ctx, bson.M{"_id": id})
	if err != nil {
		log.Error().Err(err).Str("idpID", id).Msg("Error deleting IdP configuration from MongoDB")
		return err
	}
	if result.DeletedCount == 0 {
		return errors.New("IdP configuration not found for deletion")
	}
	return nil
}

// Ensure IdPRepositoryMongo implements domain.IdPRepository
var _ domain.IdPRepository = (*IdPRepositoryMongo)(nil)
