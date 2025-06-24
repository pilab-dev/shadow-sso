package domain

import "time"

// UserFederatedIdentity links a local user account to an external identity provider.
type UserFederatedIdentity struct {
	ID               string    `bson:"_id,omitempty" json:"id,omitempty"`
	UserID           string    `bson:"user_id" json:"user_id"`                 // Foreign key to users._id
	ProviderID       string    `bson:"provider_id" json:"provider_id"`         // Foreign key to identity_providers._id
	ProviderUserID   string    `bson:"provider_user_id" json:"provider_user_id"` // User's unique ID at the external provider
	ProviderEmail    string    `bson:"provider_email,omitempty" json:"provider_email,omitempty"`
	ProviderUsername string    `bson:"provider_username,omitempty" json:"provider_username,omitempty"`
	AccessToken      string    `bson:"access_token,omitempty" json:"-"`  // Encrypted
	RefreshToken     string    `bson:"refresh_token,omitempty" json:"-"` // Encrypted
	TokenExpiresAt   *time.Time `bson:"token_expires_at,omitempty" json:"token_expires_at,omitempty"`
	CreatedAt        time.Time `bson:"created_at" json:"created_at"`
	UpdatedAt        time.Time `bson:"updated_at" json:"updated_at"`
}
