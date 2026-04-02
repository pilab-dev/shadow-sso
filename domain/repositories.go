//go:generate go run go.uber.org/mock/mockgen@latest -source=$GOFILE -destination=mocks/mock_repositories.go -package=mock_domain PublicKeyRepository,ServiceAccountRepository,UserRepository,SessionRepository,TokenRepository,AuthorizationCodeRepository,PkceRepository,DeviceAuthorizationRepository,ClientRepository,IdPRepository,UserFederatedIdentityRepository,ConfigurationRepository
package domain

import (
	"context"
	"time" // For SessionFilter
	// Added client import
)

type PasswordHasher interface {
	Hash(password string) (string, error)
	Verify(hashedPassword, password string) error
}

type FlowStore interface {
	StoreFlow(flowID string, state LoginFlowState) error
	GetFlow(flowID string) (*LoginFlowState, error)
	UpdateFlow(flowID string, state *LoginFlowState) error
	DeleteFlow(flowID string) error
	CleanupExpiredFlows()
}

type UserSessionStore interface {
	StoreUserSession(session *UserSession) error
	GetUserSession(sessionID string) (*UserSession, error)
	DeleteUserSession(sessionID string) error
	DeleteUserSessionsByUserID(userID string) error
	CleanupExpiredSessions()
}

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

// SMSService defines the interface for sending SMS messages
type SMSService interface {
	SendOTP(phoneNumber, otp string) error
}

// EmailService defines the interface for sending emails
type EmailService interface {
	SendVerificationEmail(to, name, verificationLink string) error
	SendPasswordResetEmail(to, name, resetLink string) error
	SendOTPEmail(to, otp string) error
	SendMFAEmail(to, name, otp, method string) error
}

// PushNotificationService defines the interface for sending push notifications
type PushNotificationService interface {
	SendPushNotification(deviceToken, title, body string, data map[string]interface{}) error
	SendPushNotificationToUser(userID, title, body string, data map[string]interface{}) error
	SendMFAPushChallenge(deviceToken, challengeID, ipAddress, userAgent string) error
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
	CountUsers(ctx context.Context) (int64, error)                                          // Method to count all users
	CountUsersByRole(ctx context.Context, role string) (int64, error)                       // New method to count users by role

	// Phone verification methods
	StorePhoneVerificationOtp(ctx context.Context, userID, otp string, expiresAt time.Time) error
	ClearPhoneVerificationOtp(ctx context.Context, userID string) error

	// Email MFA methods
	StoreEmailMFAOtp(ctx context.Context, userID, otp string, expiresAt time.Time) error
	ClearEmailMFAOtp(ctx context.Context, userID string) error
	UpdateEmailMFACounter(ctx context.Context, userID string, counter uint64) error
	EnableEmailMFA(ctx context.Context, userID string) error
	DisableEmailMFA(ctx context.Context, userID string) error

	// Push MFA methods
	RegisterPushMFADevice(ctx context.Context, userID, deviceToken string) error
	UnregisterPushMFADevice(ctx context.Context, userID, deviceToken string) error
	UpdatePushMFAChallenges(ctx context.Context, userID string, challenges []PushMFAChallenge) error
	EnablePushMFA(ctx context.Context, userID string) error
	DisablePushMFA(ctx context.Context, userID string) error
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
	RevokeToken(ctx context.Context, tokenValue string) error
	RevokeRefreshToken(ctx context.Context, tokenValue string) error
	RevokeTokenFamily(ctx context.Context, family string) error
	DeleteExpiredTokens(ctx context.Context) error
	GetTokenInfo(ctx context.Context, tokenValue string) (*Token, error)
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

// ConfigurationType represents different types of operational configuration
type ConfigurationType string

const (
	ConfigTypeEmail      ConfigurationType = "email"
	ConfigTypeSMS        ConfigurationType = "sms"
	ConfigTypePush       ConfigurationType = "push"
	ConfigTypeFederation ConfigurationType = "federation"
	ConfigTypeSecurity   ConfigurationType = "security"
	ConfigTypeGeneral    ConfigurationType = "general"
)

// Configuration represents a configurable operational setting stored in the database
type Configuration struct {
	ID          string            `bson:"_id,omitempty" json:"id"`
	Type        ConfigurationType `bson:"type" json:"type"`
	Key         string            `bson:"key" json:"key"`
	Value       string            `bson:"value" json:"value"` // Encrypted for sensitive data
	IsEncrypted bool              `bson:"is_encrypted" json:"is_encrypted"`
	Description string            `bson:"description" json:"description"`
	IsActive    bool              `bson:"is_active" json:"is_active"`
	CreatedAt   time.Time         `bson:"created_at" json:"created_at"`
	UpdatedAt   time.Time         `bson:"updated_at" json:"updated_at"`
	UpdatedBy   string            `bson:"updated_by" json:"updated_by"` // User ID who last updated
}

// ConfigurationRepository defines methods for managing operational configuration
type ConfigurationRepository interface {
	// Core CRUD operations
	Create(ctx context.Context, config *Configuration) error
	GetByKey(ctx context.Context, configType ConfigurationType, key string) (*Configuration, error)
	GetByType(ctx context.Context, configType ConfigurationType) ([]*Configuration, error)
	Update(ctx context.Context, config *Configuration) error
	Delete(ctx context.Context, configType ConfigurationType, key string) error

	// Bulk operations
	GetAllActive(ctx context.Context) ([]*Configuration, error)
	GetByTypeActive(ctx context.Context, configType ConfigurationType) ([]*Configuration, error)

	// Bootstrap/initialization
	CreateDefaultConfigs(ctx context.Context) error
}
