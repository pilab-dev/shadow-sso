package services

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/pilab-dev/shadow-sso/domain"
	pkgcrypto "github.com/pilab-dev/shadow-sso/pkg/crypto"
)

// ConfigurationService manages operational configuration with caching
type defaultConfigurationService struct {
	repo          domain.ConfigurationRepository
	encryptionKey []byte
	cache         map[string]*configurationCacheEntry
	cacheMutex    sync.RWMutex
	cacheTTL      time.Duration
}

// ConfigurationCacheEntry holds cached configuration data
type configurationCacheEntry struct {
	Config    *domain.Configuration
	CachedAt  time.Time
	ExpiresAt time.Time
}

// newDefaultConfigurationService creates a new configuration service (internal constructor).
func newDefaultConfigurationService(repo domain.ConfigurationRepository, encryptionKey string) (ConfigurationService, error) {
	if len(encryptionKey) != 32 {
		return nil, fmt.Errorf("encryption key must be 32 bytes for AES-256")
	}

	return &defaultConfigurationService{
		repo:          repo,
		encryptionKey: []byte(encryptionKey),
		cache:         make(map[string]*configurationCacheEntry),
		cacheTTL:      5 * time.Minute,
	}, nil
}

// NewConfigurationService creates a new configuration service (public constructor for backward compatibility).
func NewConfigurationService(repo domain.ConfigurationRepository, encryptionKey string) (*defaultConfigurationService, error) {
	if len(encryptionKey) != 32 {
		return nil, fmt.Errorf("encryption key must be 32 bytes for AES-256")
	}

	return &defaultConfigurationService{
		repo:          repo,
		encryptionKey: []byte(encryptionKey),
		cache:         make(map[string]*configurationCacheEntry),
		cacheTTL:      5 * time.Minute,
	}, nil
}

// GetString retrieves a string configuration value
func (s *defaultConfigurationService) GetString(ctx context.Context, configType domain.ConfigurationType, key string) (string, error) {
	config, err := s.getConfig(ctx, configType, key)
	if err != nil {
		return "", err
	}

	if config.IsEncrypted {
		return s.decrypt(config.Value)
	}
	return config.Value, nil
}

// GetStringWithDefault retrieves a string configuration value with a default
func (s *defaultConfigurationService) GetStringWithDefault(ctx context.Context, configType domain.ConfigurationType, key, defaultValue string) string {
	value, err := s.GetString(ctx, configType, key)
	if err != nil {
		return defaultValue
	}
	return value
}

// GetBool retrieves a boolean configuration value
func (s *defaultConfigurationService) GetBool(ctx context.Context, configType domain.ConfigurationType, key string) (bool, error) {
	strValue, err := s.GetString(ctx, configType, key)
	if err != nil {
		return false, err
	}
	return strValue == "true", nil
}

// GetBoolWithDefault retrieves a boolean configuration value with a default
func (s *defaultConfigurationService) GetBoolWithDefault(ctx context.Context, configType domain.ConfigurationType, key string, defaultValue bool) bool {
	value, err := s.GetBool(ctx, configType, key)
	if err != nil {
		return defaultValue
	}
	return value
}

// SetString sets a string configuration value
func (s *defaultConfigurationService) SetString(ctx context.Context, configType domain.ConfigurationType, key, value string, encrypt bool, description string, updatedBy string) error {
	var encryptedValue string
	var err error

	if encrypt {
		encryptedValue, err = s.encrypt(value)
		if err != nil {
			return fmt.Errorf("failed to encrypt value: %w", err)
		}
	} else {
		encryptedValue = value
	}

	config := &domain.Configuration{
		Type:        configType,
		Key:         key,
		Value:       encryptedValue,
		IsEncrypted: encrypt,
		Description: description,
		IsActive:    true,
		UpdatedAt:   time.Now(),
		UpdatedBy:   updatedBy,
	}

	// Check if config exists
	existing, err := s.repo.GetByKey(ctx, configType, key)
	if err != nil && err != domain.ErrConfigurationNotFound {
		return err
	}

	if existing != nil {
		// Update existing
		existing.Value = encryptedValue
		existing.IsEncrypted = encrypt
		existing.Description = description
		existing.UpdatedAt = time.Now()
		existing.UpdatedBy = updatedBy
		err = s.repo.Update(ctx, existing)
	} else {
		// Create new
		config.CreatedAt = time.Now()
		err = s.repo.Create(ctx, config)
	}

	if err != nil {
		return err
	}

	// Invalidate cache
	s.invalidateCache(configType, key)
	return nil
}

// GetAllByType retrieves all configurations of a specific type
func (s *defaultConfigurationService) GetAllByType(ctx context.Context, configType domain.ConfigurationType) ([]*domain.Configuration, error) {
	return s.repo.GetByTypeActive(ctx, configType)
}

// BootstrapDefaultConfigs initializes default configurations from environment variables
func (s *defaultConfigurationService) BootstrapDefaultConfigs(ctx context.Context) error {
	return s.repo.CreateDefaultConfigs(ctx)
}

// RefreshCache forces a cache refresh for all configurations
func (s *defaultConfigurationService) RefreshCache(ctx context.Context) error {
	s.cacheMutex.Lock()
	defer s.cacheMutex.Unlock()

	// Clear cache
	s.cache = make(map[string]*configurationCacheEntry)

	// Reload all active configs
	configs, err := s.repo.GetAllActive(ctx)
	if err != nil {
		return err
	}

	now := time.Now()
	for _, config := range configs {
		cacheKey := s.getCacheKey(config.Type, config.Key)
		s.cache[cacheKey] = &configurationCacheEntry{
			Config:    config,
			CachedAt:  now,
			ExpiresAt: now.Add(s.cacheTTL),
		}
	}

	return nil
}

// getConfig retrieves configuration with caching
func (s *defaultConfigurationService) getConfig(ctx context.Context, configType domain.ConfigurationType, key string) (*domain.Configuration, error) {
	cacheKey := s.getCacheKey(configType, key)

	// Check cache first
	s.cacheMutex.RLock()
	if entry, exists := s.cache[cacheKey]; exists && time.Now().Before(entry.ExpiresAt) {
		s.cacheMutex.RUnlock()
		return entry.Config, nil
	}
	s.cacheMutex.RUnlock()

	// Cache miss or expired, fetch from repository
	config, err := s.repo.GetByKey(ctx, configType, key)
	if err != nil {
		return nil, err
	}

	// Update cache
	s.cacheMutex.Lock()
	s.cache[cacheKey] = &configurationCacheEntry{
		Config:    config,
		CachedAt:  time.Now(),
		ExpiresAt: time.Now().Add(s.cacheTTL),
	}
	s.cacheMutex.Unlock()

	return config, nil
}

// invalidateCache removes a specific config from cache
func (s *defaultConfigurationService) invalidateCache(configType domain.ConfigurationType, key string) {
	s.cacheMutex.Lock()
	defer s.cacheMutex.Unlock()
	delete(s.cache, s.getCacheKey(configType, key))
}

// getCacheKey generates a cache key
func (s *defaultConfigurationService) getCacheKey(configType domain.ConfigurationType, key string) string {
	return string(configType) + ":" + key
}

// encrypt encrypts a value using AES-GCM.
func (s *defaultConfigurationService) encrypt(plaintext string) (string, error) {
	return pkgcrypto.EncryptAESGCM(s.encryptionKey, plaintext)
}

// decrypt decrypts a value using AES-GCM.
func (s *defaultConfigurationService) decrypt(ciphertext string) (string, error) {
	return pkgcrypto.DecryptAESGCM(s.encryptionKey, ciphertext)
}
