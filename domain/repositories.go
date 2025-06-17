package domain

import (
	"context"
)

// PublicKeyInfo is assumed to be defined in domain/service_account.go
// ServiceAccount is assumed to be defined in domain/service_account.go

// PublicKeyRepository defines methods for accessing service account public keys.
type PublicKeyRepository interface {
	// GetPublicKey retrieves active public key information by its ID (kid).
	GetPublicKey(ctx context.Context, keyID string) (*PublicKeyInfo, error)
}

// ServiceAccountRepository defines methods for service account data.
type ServiceAccountRepository interface {
	GetServiceAccountByClientEmail(ctx context.Context, clientEmail string) (*ServiceAccount, error)
	GetServiceAccount(ctx context.Context, id string) (*ServiceAccount, error)
}
