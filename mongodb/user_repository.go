package mongodb

import (
	"context"
	"errors"
	"fmt"
	"strconv" // For ListUsers pageToken as offset
	"time"

	"github.com/pilab-dev/shadow-sso/domain"             // Use the new domain.User
	"github.com/pilab-dev/shadow-sso/internal/auth/rbac" // Import rbac package
	"github.com/rs/zerolog/log"                          // Assuming logger
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

// UserRepository implements domain.UserRepository
type UserRepository struct {
	db    *mongo.Database
	users *mongo.Collection
}

// NewUserRepository creates a new UserRepositoryMongo.
func NewUserRepository(ctx context.Context, db *mongo.Database) (domain.UserRepository, error) {
	repo := &UserRepository{
		db:    db,
		users: db.Collection(UsersCollection), // "oauth_users"
	}
	if err := repo.createIndexes(ctx); err != nil {
		// Log the error but allow application to start if index creation fails due to existing compatible indexes.
		// Strict error checking might be needed depending on deployment strategy.
		log.Warn().Err(err).Msg("Failed to create user indexes (might be due to existing compatible indexes or other non-critical issue)")
	}
	return repo, nil
}

func (r *UserRepository) createIndexes(ctx context.Context) error {
	indexModels := []mongo.IndexModel{
		{
			Keys:    bson.D{{Key: "email", Value: 1}},                                                            // Changed from username to email
			Options: options.Index().SetUnique(true).SetCollation(&options.Collation{Locale: "en", Strength: 2}), // Case-insensitive unique email
		},
		// _id index is created automatically by MongoDB.
		{
			Keys:    bson.D{{Key: "status", Value: 1}}, // Index on status for filtering
			Options: options.Index().SetUnique(false),
		},
	}

	opts := options.CreateIndexes()
	_, err := r.users.Indexes().CreateMany(ctx, indexModels, opts)
	if err != nil {
		// It's common for index creation to fail if indexes already exist with different options.
		// Log this as a warning rather than a fatal error for idempotency.
		log.Warn().Err(err).Msg("Error creating indexes for users collection (may already exist or options conflict)")
		return fmt.Errorf("failed to create indexes for users collection: %w", err)
	}
	log.Info().Msg("Indexes for users collection ensured.")
	return nil
}

// CreateUser creates a new user.
func (r *UserRepository) CreateUser(ctx context.Context, user *domain.User) error {
	if user.ID == "" {
		user.ID = NewObjectID() // Assuming NewObjectID() is in this package or accessible (e.g. mongodb/utils.go)
	}
	if user.CreatedAt.IsZero() {
		user.CreatedAt = time.Now().UTC()
	}
	user.UpdatedAt = time.Now().UTC()
	if user.Status == "" { // Default status if not provided
		user.Status = domain.UserStatusActive // Or UserStatusPending if activation flow exists
	}

	// Initialize 2FA fields to default values
	user.IsTwoFactorEnabled = false
	user.TwoFactorMethod = "NONE"            // Or a specific constant domain.TwoFactorMethodNone
	user.TwoFactorSecret = ""                // Explicitly empty
	user.TwoFactorRecoveryCodes = []string{} // Explicitly empty slice

	// Initial Role Assignment Logic
	if len(user.Roles) == 0 { // If roles are not preset (e.g. by an admin call)
		count, err := r.users.CountDocuments(ctx, bson.M{})
		if err != nil {
			log.Error().Err(err).Msg("Failed to count users for role assignment")
			return fmt.Errorf("failed to count existing users: %w", err)
		}
		if count == 0 {
			user.Roles = []string{rbac.RoleAdmin, rbac.RoleUser} // First user is Admin + User
			log.Info().Str("userID", user.ID).Str("email", user.Email).Msg("First user registered, assigned Admin and User roles.")
		} else {
			user.Roles = []string{rbac.RoleUser} // Subsequent users are just User by default
		}
	}

	_, err := r.users.InsertOne(ctx, user)
	if err != nil {
		if mongo.IsDuplicateKeyError(err) { // Handles duplicate email or _id
			return errors.New("user with this email or ID already exists") // Consider domain-specific error
		}
		log.Error().Err(err).Interface("user", user).Msg("Error creating user in MongoDB")
		return err
	}
	return nil
}

// GetUserByID retrieves a user by their ID.
func (r *UserRepository) GetUserByID(ctx context.Context, id string) (*domain.User, error) {
	var user domain.User
	err := r.users.FindOne(ctx, bson.M{"_id": id}).Decode(&user)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, errors.New("user not found") // Consider domain.ErrUserNotFound
		}
		log.Error().Err(err).Str("id", id).Msg("Error getting user by ID from MongoDB")
		return nil, err
	}
	return &user, nil
}

// GetUserByEmail retrieves a user by their email.
func (r *UserRepository) GetUserByEmail(ctx context.Context, email string) (*domain.User, error) {
	var user domain.User
	err := r.users.FindOne(ctx, bson.M{"email": email}).Decode(&user)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, errors.New("user not found") // Consider domain.ErrUserNotFound
		}
		log.Error().Err(err).Str("email", email).Msg("Error getting user by email from MongoDB")
		return nil, err
	}
	return &user, nil
}

// UpdateUser updates an existing user.
func (r *UserRepository) UpdateUser(ctx context.Context, user *domain.User) error {
	if user.ID == "" {
		return errors.New("user ID is required for update")
	}
	user.UpdatedAt = time.Now().UTC()

	// Using ReplaceOne. For more granular updates, build a bson.M with $set.
	result, err := r.users.ReplaceOne(ctx, bson.M{"_id": user.ID}, user)
	if err != nil {
		log.Error().Err(err).Str("userID", user.ID).Msg("Error updating user in MongoDB")
		return err
	}
	if result.MatchedCount == 0 {
		return errors.New("user not found for update") // Consider domain.ErrUserNotFound
	}
	return nil
}

// DeleteUser removes a user by their ID. (Actual deletion, not soft delete)
func (r *UserRepository) DeleteUser(ctx context.Context, id string) error {
	result, err := r.users.DeleteOne(ctx, bson.M{"_id": id})
	if err != nil {
		log.Error().Err(err).Str("id", id).Msg("Error deleting user from MongoDB")
		return err
	}
	if result.DeletedCount == 0 {
		return errors.New("user not found for deletion") // Consider domain.ErrUserNotFound
	}
	return nil
}

// ListUsers retrieves a paginated list of users.
// pageToken is used as skip offset, returns next pageToken (next offset).
func (r *UserRepository) ListUsers(ctx context.Context, pageToken string, pageSize int) ([]*domain.User, string, error) {
	if pageSize <= 0 {
		pageSize = 10 // Default page size
	}
	if pageSize > 100 { // Max page size
		pageSize = 100
	}

	skip := int64(0)
	if pageToken != "" {
		parsedSkip, err := strconv.ParseInt(pageToken, 10, 64)
		if err == nil && parsedSkip > 0 {
			skip = parsedSkip
		} else if err != nil {
			log.Warn().Err(err).Str("pageToken", pageToken).Msg("Invalid pageToken, using default skip 0")
		}
	}

	findOptions := options.Find()
	findOptions.SetSkip(skip)
	findOptions.SetLimit(int64(pageSize))
	findOptions.SetSort(bson.D{{"created_at", -1}}) // Example sort, adjust as needed

	cursor, err := r.users.Find(ctx, bson.M{}, findOptions)
	if err != nil {
		log.Error().Err(err).Msg("Error listing users from MongoDB")
		return nil, "", err
	}
	defer cursor.Close(ctx)

	var users []*domain.User
	if err = cursor.All(ctx, &users); err != nil {
		log.Error().Err(err).Msg("Error decoding listed users from MongoDB")
		return nil, "", err
	}

	nextPageToken := ""
	if len(users) == pageSize {
		nextPageToken = strconv.FormatInt(skip+int64(pageSize), 10)
	}

	return users, nextPageToken, nil
}

// Ensure interface compliance
var _ domain.UserRepository = (*UserRepository)(nil)
