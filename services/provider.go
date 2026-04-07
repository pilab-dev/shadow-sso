package services

import (
	"github.com/pilab-dev/shadow-sso/domain"
)

// ServiceProvider defines an interface for accessing all service types.
// It provides interface-based access to all services for mockability and testability.
type ServiceProvider interface {
	// Core OAuth and Token Services
	OAuthService() OAuthService
	TokenService() TokenService
	PKCEService() PKCEService
	JWKSService() JWKSService

	// Client and User Services
	ClientService() ClientService
	UserService() UserService

	// Domain Services
	PhoneVerificationService() PhoneVerificationService
	MFAService() MFAService
	PushMFAService() PushMFAService
	PushNotificationService() domain.PushNotificationService

	// Two-Factor Authentication Service
	TwoFactorService() TwoFactorService

	// Federation and Identity Provider Services
	FederationService() FederationService

	// Management Services
	IDPManagementService() IDPManagementService
	ClientManagementService() ClientManagementService
	ServiceAccountService() ServiceAccountService

	// Configuration Service for operational settings
	ConfigurationService() ConfigurationService

	// OIDC Flow Stores - these might be considered services or state managers
	FlowStore() domain.FlowStore
	UserSessionStore() domain.UserSessionStore

	// Password Hasher for authentication operations
	PasswordHasher() domain.PasswordHasher
}
