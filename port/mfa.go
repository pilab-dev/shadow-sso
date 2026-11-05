package port

import (
	"context"

	"github.com/pilab-dev/shadow-sso/domain"
)

// MFAChallengeStore persists MFAChallengeRecords between ceremony steps.
type MFAChallengeStore interface {
	Put(ctx context.Context, record *domain.MFAChallengeRecord) error
	Get(ctx context.Context, key string) (*domain.MFAChallengeRecord, error)
	Consume(ctx context.Context, key string) (*domain.MFAChallengeRecord, error)
	Delete(ctx context.Context, key string) error
	CleanupExpired(ctx context.Context) error
}

// MFADirectory abstracts where MFA method records are stored.
type MFADirectory interface {
	GetUser(ctx context.Context, userID string) (*domain.User, error)
	AddMethod(ctx context.Context, userID string, method *domain.MfaMethod) error
	GetMethod(ctx context.Context, userID, methodID string) (*domain.MfaMethod, error)
	ListMethods(ctx context.Context, userID string) ([]domain.MfaMethod, error)
	UpdateMethod(ctx context.Context, userID string, method *domain.MfaMethod) error
	DeleteMethod(ctx context.Context, userID, methodID string) error
	FindByCredentialID(ctx context.Context, credentialID string) (*domain.User, *domain.MfaMethod, error)
}

// MFAProvider is the contract every MFA method implements.
type MFAProvider interface {
	Type() domain.MfaMethodType
	Name() string
	IsAvailable(ctx context.Context) error
	BeginEnrollment(ctx context.Context, user *domain.User) (*domain.MFAChallenge, error)
	CompleteEnrollment(ctx context.Context, user *domain.User, challengeKey string, response *domain.MFAVerification) (*domain.MfaMethod, error)
	BeginChallenge(ctx context.Context, user *domain.User, method *domain.MfaMethod) (*domain.MFAChallenge, error)
	VerifyChallenge(ctx context.Context, user *domain.User, method *domain.MfaMethod, challengeKey string, response *domain.MFAVerification) (*domain.User, error)
	Revoke(ctx context.Context, user *domain.User, methodID string) error
}

// MFARegistry holds available MFA providers.
type MFARegistry interface {
	Register(provider MFAProvider) error
	Get(methodType domain.MfaMethodType) (MFAProvider, bool)
	List() []MFAProvider
}

// PushMFAProvider is the minimal push MFA surface used by PushProvider.
type PushMFAProvider interface {
	CreatePushMFAChallenge(ctx context.Context, user *domain.User, ipAddress, userAgent string) (string, error)
	GetPushMFAChallengeStatus(ctx context.Context, userID, challengeID string) (string, error)
	EnablePushMFA(ctx context.Context, userID string) error
	DisablePushMFA(ctx context.Context, userID string) error
}
