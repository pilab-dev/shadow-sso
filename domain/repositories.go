package domain

import (
	"context"
)

import "time" // For SessionFilter

// PublicKeyInfo, ServiceAccount, User, Session are defined in their respective domain files.

// --- Existing Repositories (PublicKeyRepository, ServiceAccountRepository from previous steps) ---
//go:generate mockgen -source=$GOFILE -destination=../../mocks/mock_$GOPACKAGE/mock_$GOFILE -package=mock_$GOPACKAGE
type PublicKeyRepository interface {
	GetPublicKey(ctx context.Context, keyID string) (*PublicKeyInfo, error)
	CreatePublicKey(ctx context.Context, pubKeyInfo *PublicKeyInfo) error
	UpdatePublicKeyStatus(ctx context.Context, keyID string, newStatus string) error
	ListPublicKeysForServiceAccount(ctx context.Context, serviceAccountID string, onlyActive bool) ([]*PublicKeyInfo, error)
}

//go:generate mockgen -source=$GOFILE -destination=../../mocks/mock_$GOPACKAGE/mock_$GOFILE -package=mock_$GOPACKAGE
type ServiceAccountRepository interface {
	GetServiceAccount(ctx context.Context, id string) (*ServiceAccount, error)
	GetServiceAccountByClientEmail(ctx context.Context, clientEmail string) (*ServiceAccount, error)
	CreateServiceAccount(ctx context.Context, sa *ServiceAccount) error
	UpdateServiceAccount(ctx context.Context, sa *ServiceAccount) error
	DeleteServiceAccount(ctx context.Context, id string) error
}
// --- End Existing Repositories ---

//go:generate mockgen -source=$GOFILE -destination=../../mocks/mock_$GOPACKAGE/mock_$GOFILE -package=mock_$GOPACKAGE
type UserRepository interface {
	CreateUser(ctx context.Context, user *User) error
	GetUserByID(ctx context.Context, id string) (*User, error)
	GetUserByEmail(ctx context.Context, email string) (*User, error)
	UpdateUser(ctx context.Context, user *User) error
	DeleteUser(ctx context.Context, id string) error
	ListUsers(ctx context.Context, pageToken string, pageSize int) ([]*User, string, error)
}

// SessionFilter struct used by SessionRepository
type SessionFilter struct {
	UserID    string
	IPAddress string
	UserAgent string
	FromDate  time.Time
	ToDate    time.Time
	IsRevoked *bool
}

//go:generate mockgen -source=$GOFILE -destination=../../mocks/mock_$GOPACKAGE/mock_$GOFILE -package=mock_$GOPACKAGE
type SessionRepository interface {
	StoreSession(ctx context.Context, session *Session) error
	GetSessionByID(ctx context.Context, id string) (*Session, error)
	GetSessionByTokenID(ctx context.Context, tokenID string) (*Session, error)
	UpdateSession(ctx context.Context, session *Session) error
	DeleteSession(ctx context.Context, id string) error
	ListSessionsByUserID(ctx context.Context, userID string, filter SessionFilter) ([]*Session, error)
	DeleteSessionsByUserID(ctx context.Context, userID string, exceptSessionID ...string) (int64, error)
}

//go:generate mockgen -source=$GOFILE -destination=../../mocks/mock_$GOPACKAGE/mock_$GOFILE -package=mock_$GOPACKAGE
type IdPRepository interface {
	AddIdP(ctx context.Context, idp *IdentityProvider) error
	GetIdPByID(ctx context.Context, id string) (*IdentityProvider, error)
	GetIdPByName(ctx context.Context, name string) (*IdentityProvider, error)
	ListIdPs(ctx context.Context, onlyEnabled bool) ([]*IdentityProvider, error)
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
