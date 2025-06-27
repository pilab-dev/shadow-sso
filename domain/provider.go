package domain

import (
	"context" // Required by some repository methods, good practice for provider too
	"github.com/pilab-dev/shadow-sso/client"
)

// RepositoryProvider defines an interface for accessing all repository types.
// This allows for centralized repository creation and dependency injection,
// simplifying setup and testing.
type RepositoryProvider interface {
	// User related repositories
	UserRepository(ctx context.Context) UserRepository
	SessionRepository(ctx context.Context) SessionRepository
	UserFederatedIdentityRepository(ctx context.Context) UserFederatedIdentityRepository

	// Token and Auth flow related repositories
	TokenRepository(ctx context.Context) TokenRepository
	AuthorizationCodeRepository(ctx context.Context) AuthorizationCodeRepository
	PkceRepository(ctx context.Context) PkceRepository
	DeviceAuthorizationRepository(ctx context.Context) DeviceAuthorizationRepository

	// Client related repositories
	ClientRepository(ctx context.Context) client.ClientStore // client.ClientStore is the effective interface

	// Security and configuration related repositories
	PublicKeyRepository(ctx context.Context) PublicKeyRepository
	ServiceAccountRepository(ctx context.Context) ServiceAccountRepository
	IdPRepository(ctx context.Context) IdPRepository

	// Add other repository getters here as they are defined and needed.
	// Example: AuditLogRepository() AuditLogRepository
}
