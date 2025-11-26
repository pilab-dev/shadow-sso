package mongodb

import (
	"context"
	"fmt"
	"os"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"

	"github.com/pilab-dev/shadow-sso/domain"
)

// ConfigurationRepository implements domain.ConfigurationRepository
type ConfigurationRepository struct {
	collection *mongo.Collection
}

// NewConfigurationRepository creates a new MongoDB configuration repository
func NewConfigurationRepository(db *mongo.Database) *ConfigurationRepository {
	return &ConfigurationRepository{
		collection: db.Collection("configurations"),
	}
}

// Create creates a new configuration
func (r *ConfigurationRepository) Create(ctx context.Context, config *domain.Configuration) error {
	if config.ID == "" {
		config.ID = fmt.Sprintf("%s:%s", config.Type, config.Key)
	}
	config.CreatedAt = time.Now()
	config.UpdatedAt = time.Now()

	_, err := r.collection.InsertOne(ctx, config)
	return err
}

// GetByKey retrieves a configuration by type and key
func (r *ConfigurationRepository) GetByKey(ctx context.Context, configType domain.ConfigurationType, key string) (*domain.Configuration, error) {
	filter := bson.M{
		"type":      configType,
		"key":       key,
		"is_active": true,
	}

	var config domain.Configuration
	err := r.collection.FindOne(ctx, filter).Decode(&config)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, domain.ErrConfigurationNotFound
		}
		return nil, err
	}

	return &config, nil
}

// GetByType retrieves all configurations of a specific type
func (r *ConfigurationRepository) GetByType(ctx context.Context, configType domain.ConfigurationType) ([]*domain.Configuration, error) {
	filter := bson.M{"type": configType}

	cursor, err := r.collection.Find(ctx, filter)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var configs []*domain.Configuration
	for cursor.Next(ctx) {
		var config domain.Configuration
		if err := cursor.Decode(&config); err != nil {
			return nil, err
		}
		configs = append(configs, &config)
	}

	return configs, cursor.Err()
}

// Update updates an existing configuration
func (r *ConfigurationRepository) Update(ctx context.Context, config *domain.Configuration) error {
	filter := bson.M{"_id": config.ID}
	config.UpdatedAt = time.Now()

	update := bson.M{"$set": config}
	_, err := r.collection.UpdateOne(ctx, filter, update)
	return err
}

// Delete deletes a configuration
func (r *ConfigurationRepository) Delete(ctx context.Context, configType domain.ConfigurationType, key string) error {
	filter := bson.M{
		"type": configType,
		"key":  key,
	}

	_, err := r.collection.DeleteOne(ctx, filter)
	return err
}

// GetAllActive retrieves all active configurations
func (r *ConfigurationRepository) GetAllActive(ctx context.Context) ([]*domain.Configuration, error) {
	filter := bson.M{"is_active": true}

	cursor, err := r.collection.Find(ctx, filter, options.Find().SetSort(bson.M{"type": 1, "key": 1}))
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var configs []*domain.Configuration
	for cursor.Next(ctx) {
		var config domain.Configuration
		if err := cursor.Decode(&config); err != nil {
			return nil, err
		}
		configs = append(configs, &config)
	}

	return configs, cursor.Err()
}

// GetByTypeActive retrieves all active configurations of a specific type
func (r *ConfigurationRepository) GetByTypeActive(ctx context.Context, configType domain.ConfigurationType) ([]*domain.Configuration, error) {
	filter := bson.M{
		"type":      configType,
		"is_active": true,
	}

	cursor, err := r.collection.Find(ctx, filter, options.Find().SetSort(bson.M{"key": 1}))
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var configs []*domain.Configuration
	for cursor.Next(ctx) {
		var config domain.Configuration
		if err := cursor.Decode(&config); err != nil {
			return nil, err
		}
		configs = append(configs, &config)
	}

	return configs, cursor.Err()
}

// CreateDefaultConfigs initializes default configurations from environment variables
func (r *ConfigurationRepository) CreateDefaultConfigs(ctx context.Context) error {
	defaultConfigs := []struct {
		configType   domain.ConfigurationType
		key          string
		envKey       string
		description  string
		isEncrypted  bool
		defaultValue string
	}{
		// Email configurations
		{
			configType:  domain.ConfigTypeEmail,
			key:         "api_key",
			envKey:      "SSSO_RESEND_API_KEY",
			description: "Resend API key for sending emails",
			isEncrypted: true,
		},
		{
			configType:   domain.ConfigTypeEmail,
			key:          "from_email",
			envKey:       "SSSO_FROM_EMAIL",
			description:  "Default sender email address",
			isEncrypted:  false,
			defaultValue: "noreply@shadowsso.com",
		},
		{
			configType:   domain.ConfigTypeEmail,
			key:          "base_url",
			envKey:       "SSSO_NEXT_PUBLIC_BASE_URL",
			description:  "Base URL for email verification links",
			isEncrypted:  false,
			defaultValue: "http://localhost:3000",
		},

		// SMS configurations
		{
			configType:  domain.ConfigTypeSMS,
			key:         "account_sid",
			envKey:      "SSSO_TWILIO_ACCOUNT_SID",
			description: "Twilio Account SID for SMS",
			isEncrypted: true,
		},
		{
			configType:  domain.ConfigTypeSMS,
			key:         "auth_token",
			envKey:      "SSSO_TWILIO_AUTH_TOKEN",
			description: "Twilio Auth Token for SMS",
			isEncrypted: true,
		},
		{
			configType:  domain.ConfigTypeSMS,
			key:         "phone_number",
			envKey:      "SSSO_TWILIO_PHONE_NUMBER",
			description: "Twilio phone number for sending SMS",
			isEncrypted: false,
		},

		// Push notification configurations
		{
			configType:  domain.ConfigTypePush,
			key:         "project_id",
			envKey:      "SSSO_FIREBASE_PROJECT_ID",
			description: "Firebase project ID for push notifications",
			isEncrypted: false,
		},
		{
			configType:  domain.ConfigTypePush,
			key:         "credentials_path",
			envKey:      "SSSO_FIREBASE_CREDENTIALS_PATH",
			description: "Path to Firebase service account credentials",
			isEncrypted: false,
		},
	}

	for _, def := range defaultConfigs {
		// Check if config already exists
		existing, err := r.GetByKey(ctx, def.configType, def.key)
		if err != nil && err != domain.ErrConfigurationNotFound {
			return fmt.Errorf("failed to check existing config %s:%s: %w", def.configType, def.key, err)
		}

		if existing != nil {
			// Config already exists, skip
			continue
		}

		// Get value from environment
		value := os.Getenv(def.envKey)
		if value == "" && def.defaultValue != "" {
			value = def.defaultValue
		}

		if value == "" {
			// Skip configs that have no env var and no default
			continue
		}

		config := &domain.Configuration{
			Type:        def.configType,
			Key:         def.key,
			Value:       value,
			IsEncrypted: def.isEncrypted,
			Description: def.description,
			IsActive:    true,
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
			UpdatedBy:   "system",
		}

		if err := r.Create(ctx, config); err != nil {
			return fmt.Errorf("failed to create default config %s:%s: %w", def.configType, def.key, err)
		}
	}

	return nil
}
