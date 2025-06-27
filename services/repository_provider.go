package services

import (
	"context" // Required by some repository methods, good practice for provider too

	"github.com/pilab-dev/shadow-sso/domain"
)

// RepositoryProvider defines an interface for accessing all repository types.
// This allows for centralized repository creation and dependency injection,
// simplifying setup and testing.
//
//go:generate go run go.uber.org/mock/mockgen@latest -source=$GOFILE -destination=mocks/mock_$GOFILE -package=mock_$GOPACKAGE RepositoryProvider
type RepositoryProvider interface {
	// User related repositories
	UserRepository(ctx context.Context) domain.UserRepository
	SessionRepository(ctx context.Context) domain.SessionRepository
	UserFederatedIdentityRepository(ctx context.Context) domain.UserFederatedIdentityRepository

	// Token and Auth flow related repositories
	TokenRepository(ctx context.Context) domain.TokenRepository
	AuthorizationCodeRepository(ctx context.Context) domain.AuthorizationCodeRepository
	PkceRepository(ctx context.Context) domain.PkceRepository
	DeviceAuthorizationRepository(ctx context.Context) domain.DeviceAuthorizationRepository

	// Client related repositories
	ClientRepository(ctx context.Context) domain.ClientRepository // client.ClientStore is the effective interface

	// Security and configuration related repositories
	PublicKeyRepository(ctx context.Context) domain.PublicKeyRepository
	ServiceAccountRepository(ctx context.Context) domain.ServiceAccountRepository
	IdPRepository(ctx context.Context) domain.IdPRepository

	// Add other repository getters here as they are defined and needed.
	// Example: AuditLogRepository() AuditLogRepository
}
