package client

import (
	"context"
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
//
//nolint:tagliatelle
type Client struct {
	ID                string     `bson:"client_id" json:"client_id,omitempty"`
	Secret            string     `bson:"client_secret,omitempty" json:"secret,omitempty"`
	Type              ClientType `bson:"client_type" json:"type,omitempty"`
	Name              string     `bson:"client_name" json:"name,omitempty"`
	Description       string     `bson:"description,omitempty" json:"description,omitempty"`
	RedirectURIs      []string   `bson:"redirect_uris" json:"redirect_ur_is,omitempty"`
	PostLogoutURIs    []string   `bson:"post_logout_redirect_uris,omitempty" json:"post_logout_uris,omitempty"`
	AllowedScopes     []string   `bson:"allowed_scopes" json:"allowed_scopes,omitempty"`
	AllowedGrantTypes []string   `bson:"allowed_grant_types" json:"allowed_grant_types,omitempty"`
	TokenEndpointAuth string     `bson:"token_endpoint_auth_method" json:"token_endpoint_auth,omitempty"`
	JWKS              *JWKS      `bson:"jwks,omitempty" json:"jwks,omitempty"`
	JWKSUri           string     `bson:"jwks_uri,omitempty" json:"jwks_uri,omitempty"`
	Contacts          []string   `bson:"contacts,omitempty" json:"contacts,omitempty"`
	LogoURI           string     `bson:"logo_uri,omitempty" json:"logo_uri,omitempty"`
	PolicyURI         string     `bson:"policy_uri,omitempty" json:"policy_uri,omitempty"`
	TermsURI          string     `bson:"tos_uri,omitempty" json:"terms_uri,omitempty"`
	RequireConsent    bool       `bson:"require_consent" json:"require_consent,omitempty"`
	RequirePKCE       bool       `bson:"require_pkce" json:"require_pkce,omitempty"`
	CreatedAt         time.Time  `bson:"created_at" json:"created_at,omitempty"`
	UpdatedAt         time.Time  `bson:"updated_at" json:"updated_at,omitempty"`
	LastUsed          time.Time  `bson:"last_used,omitempty" json:"last_used,omitempty"`
	IsActive          bool       `bson:"is_active" json:"is_active,omitempty"`
	IsConfidential    bool       `bson:"is_confidential" json:"is_confidential,omitempty"`

	ClientLDAPAttributeEmail      string            `bson:"client_ldap_attribute_email,omitempty" json:"client_ldap_attribute_email,omitempty"`
	ClientLDAPAttributeFirstName  string            `bson:"client_ldap_attribute_first_name,omitempty" json:"client_ldap_attribute_first_name,omitempty"`
	ClientLDAPAttributeLastName   string            `bson:"client_ldap_attribute_last_name,omitempty" json:"client_ldap_attribute_last_name,omitempty"`
	ClientLDAPAttributeGroups     string            `bson:"client_ldap_attribute_groups,omitempty" json:"client_ldap_attribute_groups,omitempty"`
	ClientLDAPCustomClaimsMapping map[string]string `bson:"client_ldap_custom_claims_mapping,omitempty" json:"client_ldap_custom_claims_mapping,omitempty"`
}

// JWKS represents a JSON Web Key Set for client authentication
type JWKS struct {
	Keys []JSONWebKey `json:"keys"`
}

// JSONWebKey represents a public key in JWK format
type JSONWebKey struct {
	Kid string `json:"kid"`         // Key ID
	Kty string `json:"kty"`         // Key type
	Alg string `json:"alg"`         // Algorithm
	Use string `json:"use"`         // Key usage (e.g., "sig" for signature)
	N   string `json:"n,omitempty"` // RSA modulus
	E   string `json:"e,omitempty"` // RSA public exponent

	P string `json:"p,omitempty"` // RSA prime factor
	Q string `json:"q,omitempty"` // RSA private exponent
	D string `json:"d,omitempty"` // RSA private exponent

	Qi string `json:"qi,omitempty"` // RSA other prime factor
	Dq string `json:"dq,omitempty"` // RSA private exponent
	Dp string `json:"dp,omitempty"` // RSA private exponent
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
func (s *ClientService) CreateConfidentialClient(ctx context.Context,
	name string, redirectURIs []string, allowedScopes []string,
) (*Client, error) {
	client := &Client{
		ID:            uuid.NewString(),
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

	if err := s.store.CreateClient(ctx, client); err != nil {
		return nil, err
	}

	return client, nil
}

// CreatePublicClient creates a new public client
func (s *ClientService) CreatePublicClient(ctx context.Context,
	name string, redirectURIs []string, allowedScopes []string,
) (*Client, error) {
	client := &Client{
		ID:            uuid.NewString(),
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

	return client.RequirePKCE || client.Type == Public, nil
}

// GetClient retrieves a client by ID
func (s *ClientService) GetClient(ctx context.Context, clientID string) (*Client, error) {
	return s.store.GetClient(ctx, clientID)
}

// ValidateClient validates client credentials and returns the client if valid
func (s *ClientService) ValidateClient(ctx context.Context, clientID, clientSecret string) (*Client, error) {
	return s.store.ValidateClient(ctx, clientID, clientSecret)
}
