package domain

// ServiceAccountKey represents the structure of a downloadable service account JSON key,
// similar to Google Cloud's format.
type ServiceAccountKey struct {
	Type                   string `json:"type"`
	ProjectID              string `json:"project_id"`
	PrivateKeyID           string `json:"private_key_id"`
	PrivateKey             string `json:"private_key"`
	ClientEmail            string `json:"client_email"`
	ClientID               string `json:"client_id"`
	AuthURI                string `json:"auth_uri"`
	TokenURI               string `json:"token_uri"`
	AuthProviderX509CertURL string `json:"auth_provider_x509_cert_url"`
	ClientX509CertURL      string `json:"client_x509_cert_url"`
}

// ServiceAccount represents a service account to which keys can be associated.
// This might be extended further later.
type ServiceAccount struct {
	ID          string `bson:"_id,omitempty"` // MongoDB ID
	ProjectID   string `bson:"project_id"`
	ClientEmail string `bson:"client_email"` // Usually matches the issuer in JWTs from this SA
	ClientID    string `bson:"client_id"`    // OAuth client ID if applicable, or internal ID
	DisplayName string `bson:"display_name,omitempty"`
	Disabled    bool   `bson:"disabled,omitempty"`
	CreatedAt   int64  `bson:"created_at"`
	UpdatedAt   int64  `bson:"updated_at"`
}

// PublicKeyInfo stores information about a public key associated with a service account.
type PublicKeyInfo struct {
	ID               string `bson:"_id,omitempty"` // Key ID (private_key_id from the JSON)
	ServiceAccountID string `bson:"service_account_id"`
	PublicKey        string `bson:"public_key"` // PEM-encoded public key
	Algorithm        string `bson:"algorithm"` // e.g., "RS256"
	Status           string `bson:"status"` // e.g., "ACTIVE", "REVOKED"
	CreatedAt        int64  `bson:"created_at"`
	ExpiresAt        int64  `bson:"expires_at,omitempty"` // Optional expiry for keys
}
