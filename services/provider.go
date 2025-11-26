package services

import (
	"github.com/pilab-dev/shadow-sso/client"
	"github.com/pilab-dev/shadow-sso/domain"
	"github.com/pilab-dev/shadow-sso/internal/federation"
)

// ServiceProvider defines an interface for accessing all service types.
// It takes a domain.RepositoryProvider for initializing services with their
// necessary repository dependencies.
type ServiceProvider interface {
	// Core OAuth and Token Services
	OAuthService() *OAuthService // Assuming direct struct usage as per current code
	TokenService() *TokenService
	PKCEService() *PKCEService
	JWKSService() *JWKSService

	// Client and User Services
	ClientService() *client.ClientService // from client package
	UserService() *UserServer

	// Domain Services
	PhoneVerificationService() *domain.PhoneVerificationService
	MFAService() *domain.MFAService
	PushNotificationService() domain.PushNotificationService

	// Two-Factor Authentication Service
	TwoFactorService() *TwoFactorServer

	// Federation and Identity Provider Services
	FederationService() *federation.Service // from internal/federation

	// Configuration Service for operational settings
	ConfigurationService() *ConfigurationService

	// OIDC Flow Stores - these might be considered services or state managers
	FlowStore() domain.FlowStore
	UserSessionStore() domain.UserSessionStore

	// Consider adding other services like AuditService if it exists
}

// NewServiceProvider is a constructor function type that would be implemented
// by concrete providers (e.g., in services/service_provider_impl.go).
// This example shows a factory function signature.
// type NewServiceProviderFunc func(rp domain.RepositoryProvider, config *YourGlobalConfig) ServiceProvider
