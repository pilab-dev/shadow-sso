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

// NewUserRepository creates a new UserRepository which implements [domain.UserRepository].
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
		user.ID = NewID() // Generate UUID for new users
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
			return nil, domain.ErrUserNotFound
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
			return nil, domain.ErrUserNotFound
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
		return domain.ErrUserNotFound
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
		return domain.ErrUserNotFound
	}
	return nil
}

// CountUsers counts the total number of users in the repository.
func (r *UserRepository) CountUsers(ctx context.Context) (int64, error) {
	count, err := r.users.CountDocuments(ctx, bson.M{})
	if err != nil {
		log.Error().Err(err).Msg("Failed to count users")
		return 0, fmt.Errorf("failed to count users: %w", err)
	}
	return count, nil
}

// CountUsersByRole counts users that have a specific role.
func (r *UserRepository) CountUsersByRole(ctx context.Context, role string) (int64, error) {
	filter := bson.M{"roles": role}
	count, err := r.users.CountDocuments(ctx, filter)
	if err != nil {
		log.Error().Err(err).Str("role", role).Msg("Failed to count users by role")
		return 0, fmt.Errorf("failed to count users by role %s: %w", role, err)
	}
	return count, nil
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
	findOptions.SetSort(bson.D{{Key: "created_at", Value: -1}}) // Example sort, adjust as needed

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

// StorePhoneVerificationOtp stores a phone verification OTP for a user
func (r *UserRepository) StorePhoneVerificationOtp(ctx context.Context, userID, otp string, expiresAt time.Time) error {
	filter := bson.M{"_id": userID}
	update := bson.M{
		"$set": bson.M{
			"phone_verification_otp":            otp,
			"phone_verification_otp_expires_at": expiresAt,
			"updated_at":                        time.Now(),
		},
	}

	result, err := r.users.UpdateOne(ctx, filter, update)
	if err != nil {
		log.Error().Err(err).Str("userID", userID).Msg("Failed to store phone verification OTP")
		return fmt.Errorf("failed to store phone verification OTP: %w", err)
	}

	if result.MatchedCount == 0 {
		return domain.ErrUserNotFound
	}

	return nil
}

// ClearPhoneVerificationOtp clears the phone verification OTP for a user
func (r *UserRepository) ClearPhoneVerificationOtp(ctx context.Context, userID string) error {
	filter := bson.M{"_id": userID}
	update := bson.M{
		"$unset": bson.M{
			"phone_verification_otp":             "",
			"phone_verification_otp_expires_at":  "",
			"phone_verification_attempts":        "",
			"phone_verification_last_attempt_at": "",
		},
		"$set": bson.M{
			"updated_at": time.Now(),
		},
	}

	result, err := r.users.UpdateOne(ctx, filter, update)
	if err != nil {
		log.Error().Err(err).Str("userID", userID).Msg("Failed to clear phone verification OTP")
		return fmt.Errorf("failed to clear phone verification OTP: %w", err)
	}

	if result.MatchedCount == 0 {
		return domain.ErrUserNotFound
	}

	return nil
}

// StoreEmailMFAOtp stores an email MFA OTP for a user
func (r *UserRepository) StoreEmailMFAOtp(ctx context.Context, userID, otp string, expiresAt time.Time) error {
	filter := bson.M{"_id": userID}
	now := time.Now()
	update := bson.M{
		"$set": bson.M{
			"email_mfa_otp":            otp,
			"email_mfa_otp_expires_at": expiresAt,
			"email_mfa_last_sent_at":   &now,
			"updated_at":               now,
		},
	}

	result, err := r.users.UpdateOne(ctx, filter, update)
	if err != nil {
		log.Error().Err(err).Str("userID", userID).Msg("Failed to store email MFA OTP")
		return fmt.Errorf("failed to store email MFA OTP: %w", err)
	}

	if result.MatchedCount == 0 {
		return domain.ErrUserNotFound
	}

	return nil
}

// ClearEmailMFAOtp clears the email MFA OTP for a user
func (r *UserRepository) ClearEmailMFAOtp(ctx context.Context, userID string) error {
	filter := bson.M{"_id": userID}
	update := bson.M{
		"$unset": bson.M{
			"email_mfa_otp":            "",
			"email_mfa_otp_expires_at": "",
			"email_mfa_last_sent_at":   "",
		},
		"$set": bson.M{
			"updated_at": time.Now(),
		},
	}

	result, err := r.users.UpdateOne(ctx, filter, update)
	if err != nil {
		log.Error().Err(err).Str("userID", userID).Msg("Failed to clear email MFA OTP")
		return fmt.Errorf("failed to clear email MFA OTP: %w", err)
	}

	if result.MatchedCount == 0 {
		return domain.ErrUserNotFound
	}

	return nil
}

// UpdateEmailMFACounter updates the email MFA OTP counter for a user
func (r *UserRepository) UpdateEmailMFACounter(ctx context.Context, userID string, counter uint64) error {
	filter := bson.M{"_id": userID}
	update := bson.M{
		"$set": bson.M{
			"email_mfa_otp_counter": counter,
			"updated_at":            time.Now(),
		},
	}

	result, err := r.users.UpdateOne(ctx, filter, update)
	if err != nil {
		log.Error().Err(err).Str("userID", userID).Msg("Failed to update email MFA counter")
		return fmt.Errorf("failed to update email MFA counter: %w", err)
	}

	if result.MatchedCount == 0 {
		return domain.ErrUserNotFound
	}

	return nil
}

// EnableEmailMFA enables email MFA for a user
func (r *UserRepository) EnableEmailMFA(ctx context.Context, userID string) error {
	filter := bson.M{"_id": userID}
	update := bson.M{
		"$set": bson.M{
			"email_mfa_enabled": true,
			"updated_at":        time.Now(),
		},
	}

	result, err := r.users.UpdateOne(ctx, filter, update)
	if err != nil {
		log.Error().Err(err).Str("userID", userID).Msg("Failed to enable email MFA")
		return fmt.Errorf("failed to enable email MFA: %w", err)
	}

	if result.MatchedCount == 0 {
		return domain.ErrUserNotFound
	}

	return nil
}

// DisableEmailMFA disables email MFA for a user
func (r *UserRepository) DisableEmailMFA(ctx context.Context, userID string) error {
	filter := bson.M{"_id": userID}
	update := bson.M{
		"$unset": bson.M{
			"email_mfa_enabled":        "",
			"email_mfa_otp":            "",
			"email_mfa_otp_expires_at": "",
			"email_mfa_otp_counter":    "",
			"email_mfa_last_sent_at":   "",
		},
		"$set": bson.M{
			"updated_at": time.Now(),
		},
	}

	result, err := r.users.UpdateOne(ctx, filter, update)
	if err != nil {
		log.Error().Err(err).Str("userID", userID).Msg("Failed to disable email MFA")
		return fmt.Errorf("failed to disable email MFA: %w", err)
	}

	if result.MatchedCount == 0 {
		return domain.ErrUserNotFound
	}

	return nil
}

// RegisterPushMFADevice registers a device token for push MFA
func (r *UserRepository) RegisterPushMFADevice(ctx context.Context, userID, deviceToken string) error {
	filter := bson.M{"_id": userID}
	update := bson.M{
		"$addToSet": bson.M{
			"push_mfa_device_tokens": deviceToken,
		},
		"$set": bson.M{
			"updated_at": time.Now(),
		},
	}

	result, err := r.users.UpdateOne(ctx, filter, update)
	if err != nil {
		log.Error().Err(err).Str("userID", userID).Msg("Failed to register push MFA device")
		return fmt.Errorf("failed to register push MFA device: %w", err)
	}

	if result.MatchedCount == 0 {
		return domain.ErrUserNotFound
	}

	return nil
}

// UnregisterPushMFADevice removes a device token for push MFA
func (r *UserRepository) UnregisterPushMFADevice(ctx context.Context, userID, deviceToken string) error {
	filter := bson.M{"_id": userID}
	update := bson.M{
		"$pull": bson.M{
			"push_mfa_device_tokens": deviceToken,
		},
		"$set": bson.M{
			"updated_at": time.Now(),
		},
	}

	result, err := r.users.UpdateOne(ctx, filter, update)
	if err != nil {
		log.Error().Err(err).Str("userID", userID).Msg("Failed to unregister push MFA device")
		return fmt.Errorf("failed to unregister push MFA device: %w", err)
	}

	if result.MatchedCount == 0 {
		return domain.ErrUserNotFound
	}

	return nil
}

// UpdatePushMFAChallenges updates the push MFA challenges for a user
func (r *UserRepository) UpdatePushMFAChallenges(ctx context.Context, userID string, challenges []domain.PushMFAChallenge) error {
	filter := bson.M{"_id": userID}
	update := bson.M{
		"$set": bson.M{
			"push_mfa_challenges": challenges,
			"updated_at":          time.Now(),
		},
	}

	result, err := r.users.UpdateOne(ctx, filter, update)
	if err != nil {
		log.Error().Err(err).Str("userID", userID).Msg("Failed to update push MFA challenges")
		return fmt.Errorf("failed to update push MFA challenges: %w", err)
	}

	if result.MatchedCount == 0 {
		return domain.ErrUserNotFound
	}

	return nil
}

// EnablePushMFA enables push MFA for a user
func (r *UserRepository) EnablePushMFA(ctx context.Context, userID string) error {
	filter := bson.M{"_id": userID}
	update := bson.M{
		"$set": bson.M{
			"push_mfa_enabled": true,
			"updated_at":       time.Now(),
		},
	}

	result, err := r.users.UpdateOne(ctx, filter, update)
	if err != nil {
		log.Error().Err(err).Str("userID", userID).Msg("Failed to enable push MFA")
		return fmt.Errorf("failed to enable push MFA: %w", err)
	}

	if result.MatchedCount == 0 {
		return domain.ErrUserNotFound
	}

	return nil
}

// DisablePushMFA disables push MFA for a user
func (r *UserRepository) DisablePushMFA(ctx context.Context, userID string) error {
	filter := bson.M{"_id": userID}
	update := bson.M{
		"$unset": bson.M{
			"push_mfa_enabled":       "",
			"push_mfa_device_tokens": "",
			"push_mfa_challenges":    "",
		},
		"$set": bson.M{
			"updated_at": time.Now(),
		},
	}

	result, err := r.users.UpdateOne(ctx, filter, update)
	if err != nil {
		log.Error().Err(err).Str("userID", userID).Msg("Failed to disable push MFA")
		return fmt.Errorf("failed to disable push MFA: %w", err)
	}

	if result.MatchedCount == 0 {
		return domain.ErrUserNotFound
	}

	return nil
}

func (r *UserRepository) GetUserByEmailVerificationToken(ctx context.Context, token string) (*domain.User, error) {
	var user domain.User
	err := r.users.FindOne(ctx, bson.M{"email_verification_token": token}).Decode(&user)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, domain.ErrUserNotFound
		}
		return nil, err
	}
	return &user, nil
}

func (r *UserRepository) GetUserByPasswordResetToken(ctx context.Context, token string) (*domain.User, error) {
	var user domain.User
	err := r.users.FindOne(ctx, bson.M{"password_reset_token": token}).Decode(&user)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, domain.ErrUserNotFound
		}
		return nil, err
	}
	return &user, nil
}

func (r *UserRepository) StoreEmailVerificationToken(ctx context.Context, userID, token string, expiresAt time.Time) error {
	filter := bson.M{"_id": userID}
	update := bson.M{
		"$set": bson.M{
			"email_verification_token":            token,
			"email_verification_token_expires_at": expiresAt,
			"updated_at":                          time.Now(),
		},
	}
	result, err := r.users.UpdateOne(ctx, filter, update)
	if err != nil {
		return fmt.Errorf("failed to store email verification token: %w", err)
	}
	if result.MatchedCount == 0 {
		return domain.ErrUserNotFound
	}
	return nil
}

func (r *UserRepository) ClearEmailVerificationToken(ctx context.Context, userID string) error {
	filter := bson.M{"_id": userID}
	update := bson.M{
		"$unset": bson.M{
			"email_verification_token":            "",
			"email_verification_token_expires_at": "",
		},
		"$set": bson.M{
			"updated_at": time.Now(),
		},
	}
	result, err := r.users.UpdateOne(ctx, filter, update)
	if err != nil {
		return fmt.Errorf("failed to clear email verification token: %w", err)
	}
	if result.MatchedCount == 0 {
		return domain.ErrUserNotFound
	}
	return nil
}

func (r *UserRepository) StorePasswordResetToken(ctx context.Context, userID, token string, expiresAt time.Time) error {
	filter := bson.M{"_id": userID}
	update := bson.M{
		"$set": bson.M{
			"password_reset_token":            token,
			"password_reset_token_expires_at": expiresAt,
			"updated_at":                      time.Now(),
		},
	}
	result, err := r.users.UpdateOne(ctx, filter, update)
	if err != nil {
		return fmt.Errorf("failed to store password reset token: %w", err)
	}
	if result.MatchedCount == 0 {
		return domain.ErrUserNotFound
	}
	return nil
}

func (r *UserRepository) ClearPasswordResetToken(ctx context.Context, userID string) error {
	filter := bson.M{"_id": userID}
	update := bson.M{
		"$unset": bson.M{
			"password_reset_token":            "",
			"password_reset_token_expires_at": "",
		},
		"$set": bson.M{
			"updated_at": time.Now(),
		},
	}
	result, err := r.users.UpdateOne(ctx, filter, update)
	if err != nil {
		return fmt.Errorf("failed to clear password reset token: %w", err)
	}
	if result.MatchedCount == 0 {
		return domain.ErrUserNotFound
	}
	return nil
}

func (r *UserRepository) StoreLoginOtp(ctx context.Context, userID, otp string, methodType string, expiresAt time.Time) error {
	filter := bson.M{"_id": userID}
	update := bson.M{
		"$set": bson.M{
			"login_otp":             otp,
			"login_otp_expires_at":  expiresAt,
			"login_otp_method_type": methodType,
			"updated_at":            time.Now(),
		},
	}
	result, err := r.users.UpdateOne(ctx, filter, update)
	if err != nil {
		return fmt.Errorf("failed to store login OTP: %w", err)
	}
	if result.MatchedCount == 0 {
		return domain.ErrUserNotFound
	}
	return nil
}

func (r *UserRepository) ClearLoginOtp(ctx context.Context, userID string) error {
	filter := bson.M{"_id": userID}
	update := bson.M{
		"$unset": bson.M{
			"login_otp":             "",
			"login_otp_expires_at":  "",
			"login_otp_method_type": "",
		},
		"$set": bson.M{
			"updated_at": time.Now(),
		},
	}
	result, err := r.users.UpdateOne(ctx, filter, update)
	if err != nil {
		return fmt.Errorf("failed to clear login OTP: %w", err)
	}
	if result.MatchedCount == 0 {
		return domain.ErrUserNotFound
	}
	return nil
}

func (r *UserRepository) SetPhoneNumber(ctx context.Context, userID, phoneNumber string) error {
	filter := bson.M{"_id": userID}
	update := bson.M{
		"$set": bson.M{
			"phone_number": phoneNumber,
			"updated_at":   time.Now(),
		},
	}
	result, err := r.users.UpdateOne(ctx, filter, update)
	if err != nil {
		return fmt.Errorf("failed to set phone number: %w", err)
	}
	if result.MatchedCount == 0 {
		return domain.ErrUserNotFound
	}
	return nil
}

func (r *UserRepository) AddMfaMethod(ctx context.Context, userID string, method *domain.MfaMethod) error {
	filter := bson.M{"_id": userID}
	update := bson.M{
		"$push": bson.M{
			"mfa_methods": method,
		},
		"$set": bson.M{
			"updated_at": time.Now(),
		},
	}
	result, err := r.users.UpdateOne(ctx, filter, update)
	if err != nil {
		return fmt.Errorf("failed to add MFA method: %w", err)
	}
	if result.MatchedCount == 0 {
		return domain.ErrUserNotFound
	}
	return nil
}

func (r *UserRepository) GetMfaMethod(ctx context.Context, userID, methodID string) (*domain.MfaMethod, error) {
	user, err := r.GetUserByID(ctx, userID)
	if err != nil {
		return nil, err
	}
	for _, m := range user.MfaMethods {
		if m.ID == methodID {
			return &m, nil
		}
	}
	return nil, errors.New("MFA method not found")
}

func (r *UserRepository) ListMfaMethods(ctx context.Context, userID string) ([]domain.MfaMethod, error) {
	user, err := r.GetUserByID(ctx, userID)
	if err != nil {
		return nil, err
	}
	return user.MfaMethods, nil
}

func (r *UserRepository) VerifyMfaMethod(ctx context.Context, userID, methodID string) error {
	filter := bson.M{"_id": userID, "mfa_methods.id": methodID}
	update := bson.M{
		"$set": bson.M{
			"mfa_methods.$.verified": true,
			"updated_at":             time.Now(),
		},
	}
	result, err := r.users.UpdateOne(ctx, filter, update)
	if err != nil {
		return fmt.Errorf("failed to verify MFA method: %w", err)
	}
	if result.MatchedCount == 0 {
		return domain.ErrUserNotFound
	}
	return nil
}

func (r *UserRepository) RemoveMfaMethod(ctx context.Context, userID, methodID string) error {
	filter := bson.M{"_id": userID}
	update := bson.M{
		"$pull": bson.M{
			"mfa_methods": bson.M{"id": methodID},
		},
		"$set": bson.M{
			"updated_at": time.Now(),
		},
	}
	result, err := r.users.UpdateOne(ctx, filter, update)
	if err != nil {
		return fmt.Errorf("failed to remove MFA method: %w", err)
	}
	if result.MatchedCount == 0 {
		return domain.ErrUserNotFound
	}
	return nil
}

func (r *UserRepository) AddWebAuthnDevice(ctx context.Context, userID string, device *domain.WebAuthnDevice) error {
	filter := bson.M{"_id": userID}
	update := bson.M{
		"$push": bson.M{
			"webauthn_devices": device,
		},
		"$set": bson.M{
			"updated_at": time.Now(),
		},
	}
	result, err := r.users.UpdateOne(ctx, filter, update)
	if err != nil {
		return fmt.Errorf("failed to add WebAuthn device: %w", err)
	}
	if result.MatchedCount == 0 {
		return domain.ErrUserNotFound
	}
	return nil
}

func (r *UserRepository) GetWebAuthnDevice(ctx context.Context, userID, deviceID string) (*domain.WebAuthnDevice, error) {
	user, err := r.GetUserByID(ctx, userID)
	if err != nil {
		return nil, err
	}
	for _, d := range user.WebAuthnDevices {
		if d.ID == deviceID {
			return &d, nil
		}
	}
	return nil, errors.New("WebAuthn device not found")
}

func (r *UserRepository) ListWebAuthnDevices(ctx context.Context, userID string) ([]domain.WebAuthnDevice, error) {
	user, err := r.GetUserByID(ctx, userID)
	if err != nil {
		return nil, err
	}
	return user.WebAuthnDevices, nil
}

func (r *UserRepository) UpdateWebAuthnDeviceCounter(ctx context.Context, userID, deviceID string, newCounter int32) error {
	filter := bson.M{"_id": userID, "webauthn_devices.id": deviceID}
	update := bson.M{
		"$set": bson.M{
			"webauthn_devices.$.counter": newCounter,
			"updated_at":                 time.Now(),
		},
	}
	result, err := r.users.UpdateOne(ctx, filter, update)
	if err != nil {
		return fmt.Errorf("failed to update WebAuthn device counter: %w", err)
	}
	if result.MatchedCount == 0 {
		return domain.ErrUserNotFound
	}
	return nil
}

func (r *UserRepository) RemoveWebAuthnDevice(ctx context.Context, userID, deviceID string) error {
	filter := bson.M{"_id": userID}
	update := bson.M{
		"$pull": bson.M{
			"webauthn_devices": bson.M{"id": deviceID},
		},
		"$set": bson.M{
			"updated_at": time.Now(),
		},
	}
	result, err := r.users.UpdateOne(ctx, filter, update)
	if err != nil {
		return fmt.Errorf("failed to remove WebAuthn device: %w", err)
	}
	if result.MatchedCount == 0 {
		return domain.ErrUserNotFound
	}
	return nil
}

func (r *UserRepository) IncrementFailedLoginAttempts(ctx context.Context, userID string) (int32, error) {
	filter := bson.M{"_id": userID}
	update := bson.M{
		"$inc": bson.M{
			"failed_login_attempts": 1,
		},
		"$set": bson.M{
			"last_failed_login_time": time.Now(),
			"updated_at":             time.Now(),
		},
	}
	result, err := r.users.UpdateOne(ctx, filter, update)
	if err != nil {
		return 0, fmt.Errorf("failed to increment failed login attempts: %w", err)
	}
	if result.MatchedCount == 0 {
		return 0, domain.ErrUserNotFound
	}

	user, err := r.GetUserByID(ctx, userID)
	if err != nil {
		return 0, err
	}
	return int32(user.FailedLoginAttempts), nil
}

func (r *UserRepository) ResetFailedLoginAttempts(ctx context.Context, userID string) error {
	filter := bson.M{"_id": userID}
	update := bson.M{
		"$set": bson.M{
			"failed_login_attempts":  0,
			"last_failed_login_time": nil,
			"updated_at":             time.Now(),
		},
	}
	result, err := r.users.UpdateOne(ctx, filter, update)
	if err != nil {
		return fmt.Errorf("failed to reset failed login attempts: %w", err)
	}
	if result.MatchedCount == 0 {
		return domain.ErrUserNotFound
	}
	return nil
}

// Ensure interface compliance
var _ domain.UserRepository = (*UserRepository)(nil)
