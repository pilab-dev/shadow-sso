package client

import (
	"context"
	"crypto/rand"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/pilab-dev/shadow-sso/domain"
)

// ClientService handles client management operations
type ClientService struct {
	store domain.ClientRepository
}

// NewClientService creates a new ClientService instance
func NewClientService(store domain.ClientRepository) *ClientService {
	return &ClientService{
		store: store,
	}
}

// generateRandomString creates a cryptographically secure random string of the specified length
func generateRandomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, length)
	_, _ = rand.Read(b)

	for i := range b {
		b[i] = charset[int(b[i])%len(charset)]
	}

	return string(b)
}

// CreateConfidentialClient creates a new confidential client
func (s *ClientService) CreateConfidentialClient(ctx context.Context,
	name string, redirectURIs []string, allowedScopes []string,
) (*domain.Client, error) {
	client := &domain.Client{
		ID:            uuid.NewString(),
		Secret:        generateRandomString(32), // Generate a 32-character random string
		Type:          domain.ClientTypeConfidential,
		Name:          name,
		RedirectURIs:  redirectURIs,
		AllowedScopes: allowedScopes,
		AllowedGrantTypes: []string{
			"authorization_code",
			"client_credentials",
			"refresh_token",
		},
		TokenEndpointAuth: "client_secret_basic",
		RequireConsent:    true,
		RequirePKCE:       false,
		CreatedAt:         time.Now().UTC(),
		UpdatedAt:         time.Now().UTC(),
		IsActive:          true,
	}

	if err := s.store.CreateClient(ctx, client); err != nil {
		return nil, err
	}

	return client, nil
}

// CreatePublicClient creates a new public client
func (s *ClientService) CreatePublicClient(ctx context.Context,
	name string, redirectURIs []string, allowedScopes []string,
) (*domain.Client, error) {
	client := &domain.Client{
		ID:            uuid.NewString(),
		Type:          domain.ClientTypePublic,
		Name:          name,
		RedirectURIs:  redirectURIs,
		AllowedScopes: allowedScopes,
		AllowedGrantTypes: []string{
			"authorization_code",
			"refresh_token",
		},
		TokenEndpointAuth: "none",
		RequireConsent:    true,
		RequirePKCE:       true, // PKCE is required for public clients
		CreatedAt:         time.Now(),
		UpdatedAt:         time.Now(),
		IsActive:          true,
	}

	if err := s.store.CreateClient(ctx, client); err != nil {
		return nil, err
	}

	return client, nil
}

// ValidateRedirectURI checks if a redirect URI is valid for a client
func (s *ClientService) ValidateRedirectURI(ctx context.Context, clientID, redirectURI string) error {
	client, err := s.store.GetClient(ctx, clientID)
	if err != nil {
		return err
	}

	for _, uri := range client.RedirectURIs {
		if uri == redirectURI {
			return nil
		}
	}

	return fmt.Errorf("invalid redirect URI for client")
}

// ValidateScope checks if requested scopes are allowed for a client
func (s *ClientService) ValidateScope(ctx context.Context, clientID string, requestedScopes []string) error {
	client, err := s.store.GetClient(ctx, clientID)
	if err != nil {
		return err
	}

	allowedScopes := make(map[string]bool)
	for _, scope := range client.AllowedScopes {
		allowedScopes[scope] = true
	}

	for _, scope := range requestedScopes {
		if !allowedScopes[scope] {
			return fmt.Errorf("scope '%s' not allowed for client", scope)
		}
	}

	return nil
}

// ValidateGrantType checks if a grant type is allowed for a client
func (s *ClientService) ValidateGrantType(ctx context.Context, clientID, grantType string) error {
	client, err := s.store.GetClient(ctx, clientID)
	if err != nil {
		return err
	}

	for _, gt := range client.AllowedGrantTypes {
		if gt == grantType {
			return nil
		}
	}

	return fmt.Errorf("grant type '%s' not allowed for client", grantType)
}

// RequiresPKCE checks if PKCE is required for a client
func (s *ClientService) RequiresPKCE(ctx context.Context, clientID string) (bool, error) {
	client, err := s.store.GetClient(ctx, clientID)
	if err != nil {
		return false, err
	}

	return client.RequirePKCE || client.Type == domain.ClientTypePublic, nil
}

// GetClient retrieves a client by ID
func (s *ClientService) GetClient(ctx context.Context, clientID string) (*domain.Client, error) {
	return s.store.GetClient(ctx, clientID)
}

// ValidateClient validates client credentials and returns the client if valid
func (s *ClientService) ValidateClient(ctx context.Context, clientID, clientSecret string) (*domain.Client, error) {
	return s.store.ValidateClient(ctx, clientID, clientSecret)
}
