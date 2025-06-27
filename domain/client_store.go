//go:generate go run go.uber.org/mock/mockgen@latest -source=$GOFILE -destination=mocks/mock_$GOFILE -package=mock_domain ClientRepository
package domain

import (
	"context"
	"time"
)

// ClientType defines the type of client application. Confidential or Public
type ClientType string

const (
	// ClientTypeConfidential clients can securely store secrets
	ClientTypeConfidential ClientType = "confidential"
	// ClientTypePublic clients cannot securely store secrets (mobile apps, SPAs)
	ClientTypePublic ClientType = "public"
)

// ClientFilter defines filtering options for listing clients
type ClientFilter struct {
	Type     ClientType
	IsActive bool
	Search   string
}

// ClientRepository defines the interface for client storage and retrieval
type ClientRepository interface {
	// CreateClient creates a new OAuth2 client
	CreateClient(ctx context.Context, client *Client) error

	// GetClient retrieves a client by ID
	GetClient(ctx context.Context, clientID string) (*Client, error)

	// UpdateClient updates an existing client
	UpdateClient(ctx context.Context, client *Client) error

	// DeleteClient deletes a client
	DeleteClient(ctx context.Context, clientID string) error

	// ListClients returns all clients, with optional filtering
	ListClients(ctx context.Context, filter ClientFilter) ([]*Client, error)

	// ValidateClient validates client credentials
	ValidateClient(ctx context.Context, clientID, clientSecret string) (*Client, error)
}

// Client represents an OAuth2 client application
//
//nolint:tagliatelle
type Client struct {
	ID                string     `bson:"client_id"                           json:"client_id,omitempty"`
	Secret            string     `bson:"client_secret,omitempty"             json:"secret,omitempty"`
	Type              ClientType `bson:"client_type"                         json:"type,omitempty"`
	Name              string     `bson:"client_name"                         json:"name,omitempty"`
	Description       string     `bson:"description,omitempty"               json:"description,omitempty"`
	RedirectURIs      []string   `bson:"redirect_uris"                       json:"redirect_ur_is,omitempty"`
	PostLogoutURIs    []string   `bson:"post_logout_redirect_uris,omitempty" json:"post_logout_uris,omitempty"`
	AllowedScopes     []string   `bson:"allowed_scopes"                      json:"allowed_scopes,omitempty"`
	AllowedGrantTypes []string   `bson:"allowed_grant_types"                 json:"allowed_grant_types,omitempty"`
	TokenEndpointAuth string     `bson:"token_endpoint_auth_method"          json:"token_endpoint_auth,omitempty"`
	JWKS              *JWKS      `bson:"jwks,omitempty"                      json:"jwks,omitempty"`
	JWKSUri           string     `bson:"jwks_uri,omitempty"                  json:"jwks_uri,omitempty"`
	Contacts          []string   `bson:"contacts,omitempty"                  json:"contacts,omitempty"`
	LogoURI           string     `bson:"logo_uri,omitempty"                  json:"logo_uri,omitempty"`
	PolicyURI         string     `bson:"policy_uri,omitempty"                json:"policy_uri,omitempty"`
	TermsURI          string     `bson:"tos_uri,omitempty"                   json:"terms_uri,omitempty"`
	RequireConsent    bool       `bson:"require_consent"                     json:"require_consent,omitempty"`
	RequirePKCE       bool       `bson:"require_pkce"                        json:"require_pkce,omitempty"`
	CreatedAt         time.Time  `bson:"created_at"                          json:"created_at,omitempty"`
	UpdatedAt         time.Time  `bson:"updated_at"                          json:"updated_at,omitempty"`
	LastUsed          time.Time  `bson:"last_used,omitempty"                 json:"last_used,omitempty"`
	IsActive          bool       `bson:"is_active"                           json:"is_active,omitempty"`
	IsConfidential    bool       `bson:"is_confidential"                     json:"is_confidential,omitempty"`

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
