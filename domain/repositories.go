//go:generate go run go.uber.org/mock/mockgen@latest -source=$GOFILE -destination=mocks/mock_repositories.go -package=mock_domain PublicKeyRepository,ServiceAccountRepository,UserRepository,SessionRepository,TokenRepository,AuthorizationCodeRepository,PkceRepository,DeviceAuthorizationRepository,ClientRepository,IdPRepository,UserFederatedIdentityRepository
package domain

import (
	"context"
	"time" // For SessionFilter
	// Added client import
)

// PublicKeyInfo, ServiceAccount, User, Session are defined in their respective domain files.

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

// UserRepository defines methods for user data persistence.
type UserRepository interface {
	CreateUser(ctx context.Context, user *User) error
	GetUserByID(ctx context.Context, id string) (*User, error)
	GetUserByEmail(ctx context.Context, email string) (*User, error)
	UpdateUser(ctx context.Context, user *User) error                                       // Could also be UpdateUser(id, updates map[string]interface{})
	DeleteUser(ctx context.Context, id string) error                                        // Optional, consider soft delete by status
	ListUsers(ctx context.Context, pageToken string, pageSize int) ([]*User, string, error) // Returns users, next page token, error
	CountUsers(ctx context.Context) (int64, error)                                         // Method to count all users
	CountUsersByRole(ctx context.Context, role string) (int64, error)                      // New method to count users by role
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

// TokenRepository defines methods for managing OAuth tokens.
type TokenRepository interface {
	StoreToken(ctx context.Context, token *Token) error
	GetAccessToken(ctx context.Context, tokenValue string) (*Token, error)
	GetRefreshToken(ctx context.Context, tokenValue string) (*Token, error)
	GetRefreshTokenInfo(ctx context.Context, tokenValue string) (*TokenInfo, error)
	GetAccessTokenInfo(ctx context.Context, tokenValue string) (*TokenInfo, error)
	RevokeToken(ctx context.Context, tokenValue string) error // Typically for access tokens
	RevokeRefreshToken(ctx context.Context, tokenValue string) error
	// RevokeAllUserTokens(ctx context.Context, userID string) error // These might be better handled by iterating in service layer
	// RevokeAllClientTokens(ctx context.Context, clientID string) error // or having specific bulk operations if performance critical
	DeleteExpiredTokens(ctx context.Context) error
	GetTokenInfo(ctx context.Context, tokenValue string) (*Token, error) // General token info for introspection
}

// AuthorizationCodeRepository defines the interface for OAuth 2.0 authorization code operations.
type AuthorizationCodeRepository interface {
	SaveAuthCode(ctx context.Context, code *AuthCode) error
	GetAuthCode(ctx context.Context, code string) (*AuthCode, error)
	MarkAuthCodeAsUsed(ctx context.Context, code string) error
	DeleteExpiredAuthCodes(ctx context.Context) error
}

// PkceRepository defines the interface for OAuth 2.0 PKCE operations.
type PkceRepository interface {
	SaveCodeChallenge(ctx context.Context, code, challenge string) error
	GetCodeChallenge(ctx context.Context, code string) (string, error)
	DeleteCodeChallenge(ctx context.Context, code string) error
}

// DeviceAuthorizationRepository defines methods for managing device authorization flow data.
type DeviceAuthorizationRepository interface {
	SaveDeviceAuth(ctx context.Context, auth *DeviceCode) error
	GetDeviceAuthByDeviceCode(ctx context.Context, deviceCode string) (*DeviceCode, error)
	GetDeviceAuthByUserCode(ctx context.Context, userCode string) (*DeviceCode, error)
	ApproveDeviceAuth(ctx context.Context, userCode string, userID string) (*DeviceCode, error)
	UpdateDeviceAuthStatus(ctx context.Context, deviceCode string, status DeviceCodeStatus) error
	UpdateDeviceAuthLastPolledAt(ctx context.Context, deviceCode string) error
	DeleteExpiredDeviceAuths(ctx context.Context) error
}

// IdPRepository defines methods for Identity Provider configuration persistence.
type IdPRepository interface {
	AddIdP(ctx context.Context, idp *IdentityProvider) error
	GetIdPByID(ctx context.Context, id string) (*IdentityProvider, error)
	GetIdPByName(ctx context.Context, name string) (*IdentityProvider, error)    // Name should be unique
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
