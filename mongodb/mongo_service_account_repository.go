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

// ServiceAccountRepositoryMongo implements the domain.ServiceAccountRepository interface using MongoDB.
type ServiceAccountRepositoryMongo struct {
	collection *mongo.Collection
}

// NewServiceAccountRepositoryMongo creates a new ServiceAccountRepositoryMongo.
// It also ensures that the necessary indexes are created on the collection.
func NewServiceAccountRepositoryMongo(db *mongo.Database) (*ServiceAccountRepositoryMongo, error) {
	repo := &ServiceAccountRepositoryMongo{
		collection: db.Collection(ServiceAccountsCollection),
	}

	// Create indexes
	// Index on _id for GetServiceAccount
	// Index on client_email for GetServiceAccountByClientEmail (unique)
	// Index on project_id for potential queries listing SAs per project
	indexModels := []mongo.IndexModel{
		{
			Keys:    bson.D{{Key: "_id", Value: 1}}, // Service Account ID
			Options: options.Index().SetUnique(true),
		},
		{
			Keys:    bson.D{{Key: "client_email", Value: 1}},
			Options: options.Index().SetUnique(true),
		},
		{
			Keys:    bson.D{{Key: "project_id", Value: 1}},
			Options: options.Index().SetUnique(false),
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_, err := repo.collection.Indexes().CreateMany(ctx, indexModels)
	if err != nil {
		log.Error().Err(err).Msg("Failed to create indexes for service_accounts collection")
		return nil, err
	}
	log.Info().Msg("Indexes for service_accounts collection ensured.")
	return repo, nil
}

// GetServiceAccount retrieves a service account by its ID.
func (r *ServiceAccountRepositoryMongo) GetServiceAccount(ctx context.Context, id string) (*domain.ServiceAccount, error) {
	var sa domain.ServiceAccount
	err := r.collection.FindOne(ctx, bson.M{"_id": id}).Decode(&sa)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, errors.New("service account not found") // Or a domain specific error
		}
		log.Error().Err(err).Str("id", id).Msg("Error retrieving service account from MongoDB")
		return nil, err
	}
	return &sa, nil
}

// GetServiceAccountByClientEmail retrieves a service account by its client_email.
func (r *ServiceAccountRepositoryMongo) GetServiceAccountByClientEmail(ctx context.Context, clientEmail string) (*domain.ServiceAccount, error) {
	var sa domain.ServiceAccount
	err := r.collection.FindOne(ctx, bson.M{"client_email": clientEmail}).Decode(&sa)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, errors.New("service account not found by client_email") // Or a domain specific error
		}
		log.Error().Err(err).Str("clientEmail", clientEmail).Msg("Error retrieving service account by client_email from MongoDB")
		return nil, err
	}
	return &sa, nil
}

// CreateServiceAccount stores a new service account.
// Used by ServiceAccountService.
func (r *ServiceAccountRepositoryMongo) CreateServiceAccount(ctx context.Context, sa *domain.ServiceAccount) error {
	if sa.ID == "" {
		sa.ID = NewObjectID() // Generate a new MongoDB ObjectID if ID is not provided
	}
	if sa.CreatedAt == 0 {
	    sa.CreatedAt = time.Now().Unix()
	}
    sa.UpdatedAt = time.Now().Unix() // Set UpdatedAt on creation as well

	_, err := r.collection.InsertOne(ctx, sa)
	if err != nil {
		log.Error().Err(err).Msg("Error inserting service account into MongoDB")
		// Handle potential duplicate key error (_id, client_email)
		return err
	}
	return nil
}

// UpdateServiceAccount updates an existing service account.
// For example, to change display name or disabled status.
func (r *ServiceAccountRepositoryMongo) UpdateServiceAccount(ctx context.Context, sa *domain.ServiceAccount) error {
	if sa.ID == "" {
		return errors.New("service account ID cannot be empty for update")
	}
    filter := bson.M{"_id": sa.ID}

    // Prepare update document, ensuring not to overwrite fields not meant to be updated with zero values
    // Using a BSON M or a struct with omitempty tags is common here.
    // For simplicity, this example updates specific fields or the whole document if passed in.
    // A more robust update would use bson.M{"$set": bson.M{"field_to_update": value}}
    updateData := bson.M{
        "project_id":   sa.ProjectID,
        "client_email": sa.ClientEmail, // Be cautious if allowing email change, it's an identifier
        "client_id":    sa.ClientID,
        "display_name": sa.DisplayName,
        "disabled":     sa.Disabled,
        "updated_at":   time.Now().Unix(),
    }
    // Preserve CreatedAt if it exists
    if sa.CreatedAt != 0 {
        updateData["created_at"] = sa.CreatedAt
    }


	update := bson.M{"$set": updateData}

	result, err := r.collection.UpdateOne(ctx, filter, update)
	if err != nil {
		log.Error().Err(err).Str("id", sa.ID).Msg("Error updating service account in MongoDB")
		return err
	}
	if result.MatchedCount == 0 {
		return errors.New("service account not found for update")
	}
	return nil
}

// DeleteServiceAccount removes a service account.
// This should also handle deletion/revocation of associated public keys (cascade logic might be in service layer).
func (r *ServiceAccountRepositoryMongo) DeleteServiceAccount(ctx context.Context, id string) error {
	result, err := r.collection.DeleteOne(ctx, bson.M{"_id": id})
	if err != nil {
		log.Error().Err(err).Str("id", id).Msg("Error deleting service account from MongoDB")
		return err
	}
	if result.DeletedCount == 0 {
		return errors.New("service account not found for deletion")
	}
	return nil
}

// Ensure ServiceAccountRepositoryMongo implements domain.ServiceAccountRepository
var _ domain.ServiceAccountRepository = (*ServiceAccountRepositoryMongo)(nil)
