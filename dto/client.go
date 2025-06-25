package dto

import (
	"time"

	"github.com/pilab-dev/shadow-sso/client"
)

// ClientCreateRequest defines the payload for creating a new OAuth client.
type ClientCreateRequest struct {
	Name              string   `json:"name"`
	Type              string   `json:"type"` // "confidential" or "public"
	Description       string   `json:"description,omitempty"`
	RedirectURIs      []string `json:"redirect_uris"`
	PostLogoutURIs    []string `json:"post_logout_uris,omitempty"`
	AllowedScopes     []string `json:"allowed_scopes,omitempty"`
	AllowedGrantTypes []string `json:"allowed_grant_types,omitempty"` // e.g., "authorization_code", "refresh_token", "client_credentials"
	TokenEndpointAuth string   `json:"token_endpoint_auth,omitempty"` // e.g., "client_secret_basic", "private_key_jwt", "none"
	JWKSUri           string   `json:"jwks_uri,omitempty"`
	Contacts          []string `json:"contacts,omitempty"`
	LogoURI           string   `json:"logo_uri,omitempty"`
	PolicyURI         string   `json:"policy_uri,omitempty"`
	TermsURI          string   `json:"terms_uri,omitempty"`
	RequireConsent    bool     `json:"require_consent"`
	RequirePKCE       bool     `json:"require_pkce"`
}

// ClientUpdateRequest defines the payload for updating an existing OAuth client.
// All fields are optional.
type ClientUpdateRequest struct {
	Name              *string   `json:"name,omitempty"`
	Description       *string   `json:"description,omitempty"`
	RedirectURIs      *[]string `json:"redirect_uris,omitempty"`
	PostLogoutURIs    *[]string `json:"post_logout_uris,omitempty"`
	AllowedScopes     *[]string `json:"allowed_scopes,omitempty"`
	AllowedGrantTypes *[]string `json:"allowed_grant_types,omitempty"`
	TokenEndpointAuth *string   `json:"token_endpoint_auth,omitempty"`
	JWKSUri           *string   `json:"jwks_uri,omitempty"`
	Contacts          *[]string `json:"contacts,omitempty"`
	LogoURI           *string   `json:"logo_uri,omitempty"`
	PolicyURI         *string   `json:"policy_uri,omitempty"`
	TermsURI          *string   `json:"terms_uri,omitempty"`
	RequireConsent    *bool     `json:"require_consent,omitempty"`
	RequirePKCE       *bool     `json:"require_pkce,omitempty"`
	IsActive          *bool     `json:"is_active,omitempty"`
}

// ClientResponse defines the structure for API responses containing OAuth client information.
// The client secret is omitted for security.
type ClientResponse struct {
	ID                string              `json:"client_id"` // Mapped from client.Client.ID
	Type              client.ClientType `json:"type"`
	Name              string              `json:"name"`
	Description       string              `json:"description,omitempty"`
	RedirectURIs      []string            `json:"redirect_uris"`
	PostLogoutURIs    []string            `json:"post_logout_uris,omitempty"`
	AllowedScopes     []string            `json:"allowed_scopes,omitempty"`
	AllowedGrantTypes []string            `json:"allowed_grant_types,omitempty"`
	TokenEndpointAuth string              `json:"token_endpoint_auth,omitempty"`
	JWKSUri           string              `json:"jwks_uri,omitempty"`
	Contacts          []string            `json:"contacts,omitempty"`
	LogoURI           string              `json:"logo_uri,omitempty"`
	PolicyURI         string              `json:"policy_uri,omitempty"`
	TermsURI          string              `json:"terms_uri,omitempty"`
	RequireConsent    bool                `json:"require_consent"`
	RequirePKCE       bool                `json:"require_pkce"`
	CreatedAt         time.Time           `json:"created_at"`
	UpdatedAt         time.Time           `json:"updated_at"`
	LastUsed          time.Time           `json:"last_used,omitempty"`
	IsActive          bool                `json:"is_active"`
	// JWKS is omitted as it can be large and usually fetched via jwks_uri
}

// ToDomainClient converts ClientCreateRequest to client.Client.
// Does not set ID, Secret, CreatedAt, UpdatedAt. These are managed by the service/repository.
func ToDomainClient(dto ClientCreateRequest) *client.Client {
	return &client.Client{
		Type:              client.ClientType(dto.Type),
		Name:              dto.Name,
		Description:       dto.Description,
		RedirectURIs:      dto.RedirectURIs,
		PostLogoutURIs:    dto.PostLogoutURIs,
		AllowedScopes:     dto.AllowedScopes,
		AllowedGrantTypes: dto.AllowedGrantTypes,
		TokenEndpointAuth: dto.TokenEndpointAuth,
		JWKSUri:           dto.JWKSUri,
		Contacts:          dto.Contacts,
		LogoURI:           dto.LogoURI,
		PolicyURI:         dto.PolicyURI,
		TermsURI:          dto.TermsURI,
		RequireConsent:    dto.RequireConsent,
		RequirePKCE:       dto.RequirePKCE,
		// IsActive typically defaults to true in the service layer
	}
}

// ToDomainClientUpdate prepares a client.Client object for updates.
// This is a simplified version.
func ToDomainClientUpdate(clientID string, dto ClientUpdateRequest) *client.Client {
	c := &client.Client{
		ID: clientID, // ID must be set for update operations
	}
	if dto.Name != nil {
		c.Name = *dto.Name
	}
	if dto.Description != nil {
		c.Description = *dto.Description
	}
	if dto.RedirectURIs != nil {
		c.RedirectURIs = *dto.RedirectURIs
	}
	if dto.PostLogoutURIs != nil {
		c.PostLogoutURIs = *dto.PostLogoutURIs
	}
	if dto.AllowedScopes != nil {
		c.AllowedScopes = *dto.AllowedScopes
	}
	if dto.AllowedGrantTypes != nil {
		c.AllowedGrantTypes = *dto.AllowedGrantTypes
	}
	if dto.TokenEndpointAuth != nil {
		c.TokenEndpointAuth = *dto.TokenEndpointAuth
	}
	if dto.JWKSUri != nil {
		c.JWKSUri = *dto.JWKSUri
	}
	if dto.Contacts != nil {
		c.Contacts = *dto.Contacts
	}
	if dto.LogoURI != nil {
		c.LogoURI = *dto.LogoURI
	}
	if dto.PolicyURI != nil {
		c.PolicyURI = *dto.PolicyURI
	}
	if dto.TermsURI != nil {
		c.TermsURI = *dto.TermsURI
	}
	if dto.RequireConsent != nil {
		c.RequireConsent = *dto.RequireConsent
	}
	if dto.RequirePKCE != nil {
		c.RequirePKCE = *dto.RequirePKCE
	}
	if dto.IsActive != nil {
		c.IsActive = *dto.IsActive
	}
	return c
}

// FromDomainClient converts client.Client to ClientResponse.
func FromDomainClient(c *client.Client) *ClientResponse {
	if c == nil {
		return nil
	}
	return &ClientResponse{
		ID:                c.ID,
		Type:              c.Type,
		Name:              c.Name,
		Description:       c.Description,
		RedirectURIs:      c.RedirectURIs,
		PostLogoutURIs:    c.PostLogoutURIs,
		AllowedScopes:     c.AllowedScopes,
		AllowedGrantTypes: c.AllowedGrantTypes,
		TokenEndpointAuth: c.TokenEndpointAuth,
		JWKSUri:           c.JWKSUri,
		Contacts:          c.Contacts,
		LogoURI:           c.LogoURI,
		PolicyURI:         c.PolicyURI,
		TermsURI:          c.TermsURI,
		RequireConsent:    c.RequireConsent,
		RequirePKCE:       c.RequirePKCE,
		CreatedAt:         c.CreatedAt,
		UpdatedAt:         c.UpdatedAt,
		LastUsed:          c.LastUsed,
		IsActive:          c.IsActive,
	}
}

// FromDomainClients converts a slice of client.Client to a slice of ClientResponse.
func FromDomainClients(clients []*client.Client) []*ClientResponse {
	if clients == nil {
		return nil
	}
	responses := make([]*ClientResponse, len(clients))
	for i, cl := range clients {
		responses[i] = FromDomainClient(cl)
	}
	return responses
}
