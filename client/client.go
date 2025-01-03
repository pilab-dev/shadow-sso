package client

import (
	"crypto/rand"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// ClientType represents the type of OAuth2 client
type ClientType string

const (
	// Confidential clients can securely store secrets
	Confidential ClientType = "confidential"
	// Public clients cannot securely store secrets (mobile apps, SPAs)
	Public ClientType = "public"
)

// Client represents an OAuth2 client application
type Client struct {
	ID                string     `json:"client_id"`
	Secret            string     `json:"client_secret,omitempty"`
	Type              ClientType `json:"client_type"`
	Name              string     `json:"client_name"`
	Description       string     `json:"description,omitempty"`
	RedirectURIs      []string   `json:"redirect_uris"`
	PostLogoutURIs    []string   `json:"post_logout_redirect_uris,omitempty"`
	AllowedScopes     []string   `json:"allowed_scopes"`
	AllowedGrantTypes []string   `json:"allowed_grant_types"`
	TokenEndpointAuth string     `json:"token_endpoint_auth_method"`
	JWKS              *JWKS      `json:"jwks,omitempty"`
	JWKSUri           string     `json:"jwks_uri,omitempty"`
	Contacts          []string   `json:"contacts,omitempty"`
	LogoURI           string     `json:"logo_uri,omitempty"`
	PolicyURI         string     `json:"policy_uri,omitempty"`
	TermsURI          string     `json:"tos_uri,omitempty"`
	RequireConsent    bool       `json:"require_consent"`
	RequirePKCE       bool       `json:"require_pkce"`
	CreatedAt         time.Time  `json:"created_at"`
	UpdatedAt         time.Time  `json:"updated_at"`
	LastUsed          time.Time  `json:"last_used,omitempty"`
	IsActive          bool       `json:"is_active"`
}

// JWKS represents a JSON Web Key Set for client authentication
type JWKS struct {
	Keys []JSONWebKey `json:"keys"`
}

// JSONWebKey represents a public key in JWK format
type JSONWebKey struct {
	Kid string `json:"kid"`
	Kty string `json:"kty"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	N   string `json:"n,omitempty"` // RSA modulus
	E   string `json:"e,omitempty"` // RSA public exponent
}

// ClientStore defines the interface for client storage and retrieval
type ClientStore interface {
	// CreateClient creates a new OAuth2 client
	CreateClient(client *Client) error

	// GetClient retrieves a client by ID
	GetClient(clientID string) (*Client, error)

	// UpdateClient updates an existing client
	UpdateClient(client *Client) error

	// DeleteClient deletes a client
	DeleteClient(clientID string) error

	// ListClients returns all clients, with optional filtering
	ListClients(filter ClientFilter) ([]*Client, error)

	// ValidateClient validates client credentials
	ValidateClient(clientID, clientSecret string) (*Client, error)
}

// ClientFilter defines filtering options for listing clients
type ClientFilter struct {
	Type     ClientType
	IsActive bool
	Search   string
}

// ClientService handles client management operations
type ClientService struct {
	store ClientStore
}

// NewClientService creates a new ClientService instance
func NewClientService(store ClientStore) *ClientService {
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
func (s *ClientService) CreateConfidentialClient(name string, redirectURIs []string, allowedScopes []string) (*Client, error) {
	client := &Client{
		ID:            uuid.New().String(),
		Secret:        generateRandomString(32), // Generate a 32-character random string
		Type:          Confidential,
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

	if err := s.store.CreateClient(client); err != nil {
		return nil, err
	}

	return client, nil
}

// CreatePublicClient creates a new public client
func (s *ClientService) CreatePublicClient(name string, redirectURIs []string, allowedScopes []string) (*Client, error) {
	client := &Client{
		ID:            uuid.New().String(),
		Type:          Public,
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

	if err := s.store.CreateClient(client); err != nil {
		return nil, err
	}

	return client, nil
}

// ValidateRedirectURI checks if a redirect URI is valid for a client
func (s *ClientService) ValidateRedirectURI(clientID, redirectURI string) error {
	client, err := s.store.GetClient(clientID)
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
func (s *ClientService) ValidateScope(clientID string, requestedScopes []string) error {
	client, err := s.store.GetClient(clientID)
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
func (s *ClientService) ValidateGrantType(clientID, grantType string) error {
	client, err := s.store.GetClient(clientID)
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
func (s *ClientService) RequiresPKCE(clientID string) (bool, error) {
	client, err := s.store.GetClient(clientID)
	if err != nil {
		return false, err
	}

	return client.RequirePKCE || client.Type == Public, nil
}

// GetClient retrieves a client by ID
func (s *ClientService) GetClient(clientID string) (*Client, error) {
	return s.store.GetClient(clientID)
}

// ValidateClient validates client credentials and returns the client if valid
func (s *ClientService) ValidateClient(clientID, clientSecret string) (*Client, error) {
	return s.store.ValidateClient(clientID, clientSecret)
}
