package dto

import (
	"time"

	"github.com/pilab-dev/shadow-sso/domain"
)

// IdentityProviderCreateRequest defines the payload for creating a new Identity Provider.
type IdentityProviderCreateRequest struct {
	Name              string                       `json:"name"`
	Type              domain.IdPType               `json:"type"`
	IsEnabled         bool                         `json:"is_enabled"`
	OIDCClientID      string                       `json:"oidc_client_id,omitempty"`
	OIDCClientSecret  string                       `json:"oidc_client_secret,omitempty"` // Consider how to handle this securely
	OIDCIssuerURL     string                       `json:"oidc_issuer_url,omitempty"`
	OIDCScopes        []string                     `json:"oidc_scopes,omitempty"`
	AttributeMappings []domain.AttributeMapping `json:"attribute_mappings,omitempty"`
}

// IdentityProviderUpdateRequest defines the payload for updating an existing Identity Provider.
// Most fields are optional.
type IdentityProviderUpdateRequest struct {
	Name              *string                      `json:"name,omitempty"`
	IsEnabled         *bool                        `json:"is_enabled,omitempty"`
	OIDCClientID      *string                      `json:"oidc_client_id,omitempty"`
	OIDCClientSecret  *string                      `json:"oidc_client_secret,omitempty"` // Consider how to handle this securely
	OIDCIssuerURL     *string                      `json:"oidc_issuer_url,omitempty"`
	OIDCScopes        *[]string                    `json:"oidc_scopes,omitempty"`
	AttributeMappings *[]domain.AttributeMapping `json:"attribute_mappings,omitempty"`
}

// IdentityProviderResponse defines the structure for API responses containing Identity Provider information.
type IdentityProviderResponse struct {
	ID                string                       `json:"id"`
	Name              string                       `json:"name"`
	Type              domain.IdPType               `json:"type"`
	IsEnabled         bool                         `json:"is_enabled"`
	OIDCClientID      string                       `json:"oidc_client_id,omitempty"`
	OIDCIssuerURL     string                       `json:"oidc_issuer_url,omitempty"` // ClientSecret is omitted for security
	OIDCScopes        []string                     `json:"oidc_scopes,omitempty"`
	AttributeMappings []domain.AttributeMapping `json:"attribute_mappings,omitempty"`
	CreatedAt         time.Time                    `json:"created_at"`
	UpdatedAt         time.Time                    `json:"updated_at"`
}

// ToDomainIdentityProvider converts IdentityProviderCreateRequest to domain.IdentityProvider.
// Note: This function does not set ID, CreatedAt, or UpdatedAt.
func ToDomainIdentityProvider(dto IdentityProviderCreateRequest) *domain.IdentityProvider {
	return &domain.IdentityProvider{
		Name:              dto.Name,
		Type:              dto.Type,
		IsEnabled:         dto.IsEnabled,
		OIDCClientID:      dto.OIDCClientID,
		OIDCClientSecret:  dto.OIDCClientSecret, // Service layer should handle encryption/storage
		OIDCIssuerURL:     dto.OIDCIssuerURL,
		OIDCScopes:        dto.OIDCScopes,
		AttributeMappings: dto.AttributeMappings,
	}
}

// ToDomainIdentityProviderUpdate converts IdentityProviderUpdateRequest to a domain.IdentityProvider
// intended for updates. It only sets fields that are not nil in the DTO.
// The existing *domain.IdentityProvider should be fetched first and then updated.
// This is a helper to prepare the update struct, not a complete update function.
// The service layer would typically fetch the existing entity, apply changes, then save.
// For now, this mapper will create a new domain.IdentityProvider with the ID set and only updated fields.
// A more sophisticated approach would be to return a map[string]interface{} for partial updates
// or directly modify an existing domain.IdentityProvider object.
func ToDomainIdentityProviderUpdate(idpID string, dto IdentityProviderUpdateRequest) *domain.IdentityProvider {
	// This is a simplified version. In a real scenario, you'd fetch the existing IdP
	// and apply updates to it. Here, we construct a new one with only the fields to be updated.
	// The service layer will need to handle merging this with the existing entity.
	idp := &domain.IdentityProvider{
		ID: idpID, // ID must be set for update operations
	}
	if dto.Name != nil {
		idp.Name = *dto.Name
	}
	// Type is generally not updatable or requires special handling. Omitting for now.
	if dto.IsEnabled != nil {
		idp.IsEnabled = *dto.IsEnabled
	}
	if dto.OIDCClientID != nil {
		idp.OIDCClientID = *dto.OIDCClientID
	}
	if dto.OIDCClientSecret != nil {
		idp.OIDCClientSecret = *dto.OIDCClientSecret // Service layer should handle encryption/storage
	}
	if dto.OIDCIssuerURL != nil {
		idp.OIDCIssuerURL = *dto.OIDCIssuerURL
	}
	if dto.OIDCScopes != nil {
		idp.OIDCScopes = *dto.OIDCScopes
	}
	if dto.AttributeMappings != nil {
		idp.AttributeMappings = *dto.AttributeMappings
	}
	// CreatedAt and UpdatedAt are managed by the repository/service layer.
	return idp
}

// FromDomainIdentityProvider converts domain.IdentityProvider to IdentityProviderResponse.
func FromDomainIdentityProvider(idp *domain.IdentityProvider) *IdentityProviderResponse {
	if idp == nil {
		return nil
	}
	return &IdentityProviderResponse{
		ID:                idp.ID,
		Name:              idp.Name,
		Type:              idp.Type,
		IsEnabled:         idp.IsEnabled,
		OIDCClientID:      idp.OIDCClientID,
		OIDCIssuerURL:     idp.OIDCIssuerURL, // OIDCClientSecret is intentionally omitted
		OIDCScopes:        idp.OIDCScopes,
		AttributeMappings: idp.AttributeMappings,
		CreatedAt:         idp.CreatedAt,
		UpdatedAt:         idp.UpdatedAt,
	}
}

// FromDomainIdentityProviders converts a slice of domain.IdentityProvider to a slice of IdentityProviderResponse.
func FromDomainIdentityProviders(idps []*domain.IdentityProvider) []*IdentityProviderResponse {
	if idps == nil {
		return nil
	}
	responses := make([]*IdentityProviderResponse, len(idps))
	for i, idp := range idps {
		responses[i] = FromDomainIdentityProvider(idp)
	}
	return responses
}
