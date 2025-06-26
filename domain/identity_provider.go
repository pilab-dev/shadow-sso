package domain

import "time"

// IdPType defines the type of the external Identity Provider.
type IdPType string

const (
	IdPTypeOIDC IdPType = "OIDC"
	IdPTypeSAML IdPType = "SAML" // Future support
	IdPTypeLDAP IdPType = "LDAP"
)

// AttributeMapping defines how to map claims from an external IdP to local user attributes.
// Example: "email" -> "User.Email", "given_name" -> "User.FirstName"
// For simplicity, keeping this as a direct map for now. More complex mapping rules might be needed.
type AttributeMapping struct {
	ExternalAttributeName string `bson:"external_attribute_name" json:"external_attribute_name"`
	LocalUserAttribute    string `bson:"local_user_attribute" json:"local_user_attribute"` // e.g., "Email", "FirstName", "LastName", "Roles"
}

// IdentityProvider holds the configuration for an external IdP.
type IdentityProvider struct {
	ID        string  `bson:"_id,omitempty" json:"id,omitempty"` // Unique ID for this IdP config
	Name      string  `bson:"name,unique" json:"name"`           // User-friendly name (e.g., "Login with Google")
	Type      IdPType `bson:"type" json:"type"`                  // OIDC or SAML
	IsEnabled bool    `bson:"is_enabled" json:"is_enabled"`      // Whether this IdP is active for login

	// OIDC Specific Fields (if Type is OIDC)
	OIDCClientID     string   `bson:"oidc_client_id,omitempty" json:"oidc_client_id,omitempty"`
	OIDCClientSecret string   `bson:"oidc_client_secret,omitempty" json:"-"`                      // Store encrypted or in secrets manager
	OIDCIssuerURL    string   `bson:"oidc_issuer_url,omitempty" json:"oidc_issuer_url,omitempty"` // e.g., https://accounts.google.com
	OIDCScopes       []string `bson:"oidc_scopes,omitempty" json:"oidc_scopes,omitempty"`         // e.g., ["openid", "profile", "email"]
	// OIDCResponseType string `bson:"oidc_response_type,omitempty" json:"oidc_response_type,omitempty"` // e.g., "code"
	// OIDCEndpoints can often be discovered via IssuerURL/.well-known/openid-configuration

	// SAML Specific Fields (if Type is SAML - for future use)
	// SAMLEntityID string `bson:"saml_entity_id,omitempty" json:"saml_entity_id,omitempty"`
	// SAMLIdPMetadataURL string `bson:"saml_idp_metadata_url,omitempty" json:"saml_idp_metadata_url,omitempty"`
	// SAMLACSURL string `bson:"saml_acs_url,omitempty" json:"saml_acs_url,omitempty"` // Our Assertion Consumer Service URL
	// SAMLSLOURL string `bson:"saml_slo_url,omitempty" json:"saml_slo_url,omitempty"` // Our Single Logout URL

	AttributeMappings []AttributeMapping `bson:"attribute_mappings,omitempty" json:"attribute_mappings,omitempty"`
	// Example: Map "email" from IdP to local "Email", "name" to "FirstName" + "LastName" (needs logic)

	CreatedAt time.Time `bson:"created_at" json:"created_at"`
	UpdatedAt time.Time `bson:"updated_at" json:"updated_at"`

	LDAP LDAPConfig `bson:"ldap_config,omitempty" json:"ldap_config,omitempty"`
}

type LDAPConfig struct {
	ServerURL          string `bson:"server_url,omitempty"           json:"server_url,omitempty"`
	BaseDN             string `bson:"base_dn,omitempty"              json:"base_dn,omitempty"`
	BindDN             string `bson:"bind_dn,omitempty"              json:"bind_dn,omitempty"`
	BindPassword       string `bson:"bind_password,omitempty"        json:"bind_password,omitempty"`
	UserBaseDN         string `bson:"user_base_dn,omitempty"         json:"user_base_dn,omitempty"`
	UserFilter         string `bson:"user_filter,omitempty"          json:"user_filter,omitempty"`
	AttributeEmail     string `bson:"attribute_email,omitempty"      json:"attribute_email,omitempty"`
	AttributeFirstName string `bson:"attribute_first_name,omitempty" json:"attribute_first_name,omitempty"`
	AttributeLastName  string `bson:"attribute_last_name,omitempty"  json:"attribute_last_name,omitempty"`
	AttributeUsername  string `bson:"attribute_username,omitempty"   json:"attribute_username,omitempty"`
	AttributeGroups    string `bson:"attribute_groups,omitempty"     json:"attribute_groups,omitempty"`
	StartTLS           bool   `bson:"start_tls,omitempty"            json:"start_tls,omitempty"`
	SkipTLSVerify      bool   `bson:"skip_tls_verify,omitempty"      json:"skip_tls_verify,omitempty"`
}
