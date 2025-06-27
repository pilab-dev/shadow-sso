package services

import (
	"github.com/pilab-dev/shadow-sso/client"
	"github.com/pilab-dev/shadow-sso/internal/federation"
	"github.com/pilab-dev/shadow-sso/internal/oidcflow"
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

	// Federation and Identity Provider Services
	FederationService() *federation.Service // from internal/federation
	// ServiceAccountService() *ServiceAccountService
	// TwoFactorService() *TwoFactorService // 2FA Service
	// UserService() *UserService
	// AuthService() *AuthService // Assuming this is a key service
	// Utilities / Helper Services often configured at service layer
	// PasswordHasher() PasswordHasher // Interface for password hashing

	// OIDC Flow Stores - these might be considered services or state managers
	FlowStore() *oidcflow.InMemoryFlowStore               // Or an interface if it becomes persistent
	UserSessionStore() *oidcflow.InMemoryUserSessionStore // Or an interface

	// Consider adding other services like AuditService if it exists
}

// NewServiceProvider is a constructor function type that would be implemented
// by concrete providers (e.g., in services/service_provider_impl.go).
// This example shows a factory function signature.
// type NewServiceProviderFunc func(rp domain.RepositoryProvider, config *YourGlobalConfig) ServiceProvider
