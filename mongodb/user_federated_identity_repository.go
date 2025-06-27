package mongodb

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/pilab-dev/shadow-sso/domain"
	"github.com/rs/zerolog/log"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

const UserFederatedIdentitiesCollection = "user_federated_identities"

// UserFederatedIdentityRepositoryMongo implements domain.UserFederatedIdentityRepository
type UserFederatedIdentityRepositoryMongo struct {
	collection *mongo.Collection
	idpRepo    domain.IdPRepository // To map providerName to providerID if needed, or ensure consistency
}

// NewUserFederatedIdentityRepositoryMongo creates a new UserFederatedIdentityRepositoryMongo.
func NewUserFederatedIdentityRepositoryMongo(ctx context.Context, db *mongo.Database, idpRepo domain.IdPRepository) (domain.UserFederatedIdentityRepository, error) {
	repo := &UserFederatedIdentityRepositoryMongo{
		collection: db.Collection(UserFederatedIdentitiesCollection),
		idpRepo:    idpRepo,
	}
	if err := repo.createIndexes(ctx); err != nil {
		log.Warn().Err(err).Msg("Failed to create user_federated_identities indexes")
		// Depending on strictness, might return error:
		// return nil, fmt.Errorf("failed to create user_federated_identities indexes: %w", err)
	}
	return repo, nil
}

func (r *UserFederatedIdentityRepositoryMongo) createIndexes(ctx context.Context) error {
	indexModels := []mongo.IndexModel{
		{
			// Ensures a local user can only link one account from a specific provider.
			Keys:    bson.D{{Key: "user_id", Value: 1}, {Key: "provider_id", Value: 1}},
			Options: options.Index().SetUnique(true),
		},
		{
			// Ensures a specific external identity (e.g., Google User ID for Google provider)
			// can only be linked to one local user.
			Keys:    bson.D{{Key: "provider_id", Value: 1}, {Key: "provider_user_id", Value: 1}},
			Options: options.Index().SetUnique(true),
		},
		{
			// To quickly find all linked identities for a given local user.
			Keys:    bson.D{{Key: "user_id", Value: 1}},
			Options: options.Index(),
		},
		// Optional: Index on provider_email if searching by it becomes common,
		// but be mindful of PII and query patterns.
		// {
		//  Keys:    bson.D{{Key: "provider_id", Value: 1}, {Key: "provider_email", Value: 1}},
		//  Options: options.Index().SetSparse(true), // If provider_email can be empty
		// },
	}

	_, err := r.collection.Indexes().CreateMany(ctx, indexModels)
	if err != nil {
		return fmt.Errorf("failed to create indexes for %s collection: %w", UserFederatedIdentitiesCollection, err)
	}
	log.Info().Msgf("Indexes for %s collection ensured.", UserFederatedIdentitiesCollection)
	return nil
}

// resolveProviderID takes a provider name (e.g., "google") and gets its canonical ID
// from the IdPRepository. This ensures consistency if using provider_id in documents.
func (r *UserFederatedIdentityRepositoryMongo) resolveProviderID(ctx context.Context, providerName string) (string, error) {
	idp, err := r.idpRepo.GetIdPByName(ctx, providerName)
	if err != nil {
		return "", fmt.Errorf("failed to resolve provider name '%s': %w", providerName, err)
	}
	if idp == nil {
		return "", fmt.Errorf("provider '%s' not found", providerName)
	}
	return idp.ID, nil
}

func (r *UserFederatedIdentityRepositoryMongo) Create(ctx context.Context, identity *domain.UserFederatedIdentity) error {
	if identity.ID == "" {
		identity.ID = NewObjectID()
	}
	identity.CreatedAt = time.Now().UTC()
	identity.UpdatedAt = time.Now().UTC()

	// If identity.ProviderID is not set but a conceptual providerName was used to construct it,
	// this is where it should be resolved. Assuming ProviderID is correctly set before calling.
	if identity.ProviderID == "" {
		return errors.New("ProviderID is required for federated identity")
	}


	_, err := r.collection.InsertOne(ctx, identity)
	if err != nil {
		if mongo.IsDuplicateKeyError(err) {
			// This could be due to (user_id, provider_id) duplicate or (provider_id, provider_user_id) duplicate.
			return errors.New("federated identity link already exists or conflicts with an existing one")
		}
		log.Error().Err(err).Interface("identity", identity).Msg("Error creating federated identity")
		return err
	}
	return nil
}

func (r *UserFederatedIdentityRepositoryMongo) GetByProviderUserID(ctx context.Context, providerName, providerUserID string) (*domain.UserFederatedIdentity, error) {
	providerID, err := r.resolveProviderID(ctx, providerName)
	if err != nil {
		return nil, err
	}

	var identity domain.UserFederatedIdentity
	filter := bson.M{"provider_id": providerID, "provider_user_id": providerUserID}
	err = r.collection.FindOne(ctx, filter).Decode(&identity)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, errors.New("federated identity not found") // Consider domain specific error
		}
		log.Error().Err(err).Str("providerName", providerName).Str("providerUserID", providerUserID).Msg("Error getting federated identity by provider user ID")
		return nil, err
	}
	return &identity, nil
}

func (r *UserFederatedIdentityRepositoryMongo) GetByUserIDAndProvider(ctx context.Context, userID, providerName string) (*domain.UserFederatedIdentity, error) {
	providerID, err := r.resolveProviderID(ctx, providerName)
	if err != nil {
		return nil, err
	}

	var identity domain.UserFederatedIdentity
	filter := bson.M{"user_id": userID, "provider_id": providerID}
	err = r.collection.FindOne(ctx, filter).Decode(&identity)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, errors.New("federated identity not found for this user and provider") // Consider domain specific error
		}
		log.Error().Err(err).Str("userID", userID).Str("providerName", providerName).Msg("Error getting federated identity by user ID and provider")
		return nil, err
	}
	return &identity, nil
}

func (r *UserFederatedIdentityRepositoryMongo) ListByUserID(ctx context.Context, userID string) ([]*domain.UserFederatedIdentity, error) {
	filter := bson.M{"user_id": userID}
	cursor, err := r.collection.Find(ctx, filter, options.Find().SetSort(bson.D{{"created_at", 1}}))
	if err != nil {
		log.Error().Err(err).Str("userID", userID).Msg("Error listing federated identities by user ID")
		return nil, err
	}
	defer cursor.Close(ctx)

	var identities []*domain.UserFederatedIdentity
	if err = cursor.All(ctx, &identities); err != nil {
		log.Error().Err(err).Str("userID", userID).Msg("Error decoding listed federated identities")
		return nil, err
	}
	return identities, nil
}

func (r *UserFederatedIdentityRepositoryMongo) Delete(ctx context.Context, id string) error {
	result, err := r.collection.DeleteOne(ctx, bson.M{"_id": id})
	if err != nil {
		log.Error().Err(err).Str("id", id).Msg("Error deleting federated identity by ID")
		return err
	}
	if result.DeletedCount == 0 {
		return errors.New("federated identity not found for deletion")
	}
	return nil
}

func (r *UserFederatedIdentityRepositoryMongo) DeleteByUserIDAndProvider(ctx context.Context, userID, providerName string) error {
	providerID, err := r.resolveProviderID(ctx, providerName)
	if err != nil {
		// If provider doesn't exist, there's nothing to delete by its ID.
		// However, this implies a configuration issue or incorrect providerName passed.
		log.Warn().Err(err).Str("userID", userID).Str("providerName", providerName).Msg("Cannot delete federated identity: provider name resolution failed")
		return err
	}

	result, err := r.collection.DeleteOne(ctx, bson.M{"user_id": userID, "provider_id": providerID})
	if err != nil {
		log.Error().Err(err).Str("userID", userID).Str("providerName", providerName).Msg("Error deleting federated identity by user ID and provider")
		return err
	}
	if result.DeletedCount == 0 {
		return errors.New("federated identity not found for deletion by user ID and provider")
	}
	return nil
}

// Ensure interface compliance
var _ domain.UserFederatedIdentityRepository = (*UserFederatedIdentityRepositoryMongo)(nil)
