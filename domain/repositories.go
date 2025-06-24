package domain

import (
	"context"
)

import "time" // For SessionFilter

// PublicKeyInfo, ServiceAccount, User, Session are defined in their respective domain files.

// --- Existing Repositories (PublicKeyRepository, ServiceAccountRepository from previous steps) ---
type PublicKeyRepository interface {
	GetPublicKey(ctx context.Context, keyID string) (*PublicKeyInfo, error)
	// Add CreatePublicKey, UpdatePublicKeyStatus etc. if they should be part of the interface
	// For now, assuming they are used internally by ServiceAccountService or directly via mongo implementation.
	// Let's add them to the interface for completeness as they were implemented.
	CreatePublicKey(ctx context.Context, pubKeyInfo *PublicKeyInfo) error
	UpdatePublicKeyStatus(ctx context.Context, keyID string, newStatus string) error
	ListPublicKeysForServiceAccount(ctx context.Context, serviceAccountID string, onlyActive bool) ([]*PublicKeyInfo, error)
}

type ServiceAccountRepository interface {
	GetServiceAccount(ctx context.Context, id string) (*ServiceAccount, error)
	GetServiceAccountByClientEmail(ctx context.Context, clientEmail string) (*ServiceAccount, error)
	CreateServiceAccount(ctx context.Context, sa *ServiceAccount) error
	UpdateServiceAccount(ctx context.Context, sa *ServiceAccount) error
	DeleteServiceAccount(ctx context.Context, id string) error
}
// --- End Existing Repositories ---

// UserRepository defines methods for user data persistence.
type UserRepository interface {
	CreateUser(ctx context.Context, user *User) error
	GetUserByID(ctx context.Context, id string) (*User, error)
	GetUserByEmail(ctx context.Context, email string) (*User, error)
	UpdateUser(ctx context.Context, user *User) error // Could also be UpdateUser(id, updates map[string]interface{})
	DeleteUser(ctx context.Context, id string) error    // Optional, consider soft delete by status
	ListUsers(ctx context.Context, pageToken string, pageSize int) ([]*User, string, error) // Returns users, next page token, error
}

// SessionRepository defines methods for user session persistence.
type SessionFilter struct {
	UserID    string
	IPAddress string
	UserAgent string
	FromDate  time.Time
	ToDate    time.Time
	IsRevoked *bool // Pointer to bool to allow filtering by true/false or ignoring if nil
}
type SessionRepository interface {
	StoreSession(ctx context.Context, session *Session) error
	GetSessionByID(ctx context.Context, id string) (*Session, error) // Typically by session_id or token_id
	GetSessionByTokenID(ctx context.Context, tokenID string) (*Session, error)
	UpdateSession(ctx context.Context, session *Session) error // e.g., to revoke it
	DeleteSession(ctx context.Context, id string) error
	ListSessionsByUserID(ctx context.Context, userID string, filter SessionFilter) ([]*Session, error)
	DeleteSessionsByUserID(ctx context.Context, userID string, exceptSessionID ...string) (int64, error) // Returns count of deleted
}

// TokenRepository is an interface that ssso.TokenService depends on for user OAuth tokens.
// Its methods are: StoreToken, GetAccessToken, RevokeToken, GetRefreshTokenInfo, GetAccessTokenInfo.
// This interface should also be formally defined here or in the ssso package if not already.
// For now, we assume it's defined in ssso package or implicitly by its usage.
// If ssso.TokenRepository is a concrete type, it might need refactoring to an interface.

// IdPRepository defines methods for Identity Provider configuration persistence.
type IdPRepository interface {
	AddIdP(ctx context.Context, idp *IdentityProvider) error
	GetIdPByID(ctx context.Context, id string) (*IdentityProvider, error)
	GetIdPByName(ctx context.Context, name string) (*IdentityProvider, error) // Name should be unique
	ListIdPs(ctx context.Context, onlyEnabled bool) ([]*IdentityProvider, error) // Option to list only enabled IdPs
	UpdateIdP(ctx context.Context, idp *IdentityProvider) error
	DeleteIdP(ctx context.Context, id string) error
}

// UserFederatedIdentityRepository defines methods for managing user federated identity links.
type UserFederatedIdentityRepository interface {
	Create(ctx context.Context, identity *UserFederatedIdentity) error
	GetByProviderUserID(ctx context.Context, providerName, providerUserID string) (*UserFederatedIdentity, error)
	GetByUserIDAndProvider(ctx context.Context, userID, providerName string) (*UserFederatedIdentity, error)
	ListByUserID(ctx context.Context, userID string) ([]*UserFederatedIdentity, error)
	Delete(ctx context.Context, id string) error
	DeleteByUserIDAndProvider(ctx context.Context, userID, providerName string) error
	// FindByEmail (Optional): May be useful during account linking/merging user discovery.
	// FindByProviderEmail(ctx context.Context, providerName, email string) (*UserFederatedIdentity, error)
}
