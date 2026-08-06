package ssso

import (
	"context"
	"errors"
	"testing"

	"github.com/pilab-dev/shadow-sso/domain"
	mock_domain "github.com/pilab-dev/shadow-sso/domain/mocks"
	"github.com/pilab-dev/shadow-sso/mongodb"
	"github.com/rs/zerolog"
	"go.uber.org/mock/gomock"
)

// wantBootstrapClient is the exact client ensureBootstrapSSSOCTLClient must
// create: every field asserted via gomock.Eq deep-equality.
func wantBootstrapClient() *domain.Client {
	return &domain.Client{
		ID:                "sssoctl",
		Name:              "ssoctl CLI",
		Type:              domain.ClientTypePublic,
		IsActive:          true,
		IsConfidential:    false,
		TokenEndpointAuth: "none",
		AllowedGrantTypes: []string{"urn:ietf:params:oauth:grant-type:device_code", "refresh_token"},
		AllowedScopes:     []string{"openid", "profile", "email"},
		RequirePKCE:       false,
		RequireConsent:    false,
	}
}

// TestEnsureBootstrapSSSOCTLClient_CreatesOnFreshRepo verifies that on a fresh
// repository (GetClient -> ErrClientNotFound) the sssoctl client is created
// exactly once with all expected fields.
func TestEnsureBootstrapSSSOCTLClient_CreatesOnFreshRepo(t *testing.T) {
	ctrl := gomock.NewController(t)
	repo := mock_domain.NewMockClientRepository(ctrl)

	repo.EXPECT().GetClient(gomock.Any(), "sssoctl").Return(nil, domain.ErrClientNotFound)
	repo.EXPECT().
		CreateClient(gomock.Any(), gomock.Eq(wantBootstrapClient())).
		Return(nil).
		Times(1)

	if err := ensureBootstrapSSSOCTLClient(context.Background(), repo, zerolog.Nop()); err != nil {
		t.Fatalf("expected nil error, got: %v", err)
	}
}

// TestEnsureBootstrapSSSOCTLClient_Idempotent verifies that when the client
// already exists, repeated invocations never call CreateClient.
func TestEnsureBootstrapSSSOCTLClient_Idempotent(t *testing.T) {
	ctrl := gomock.NewController(t)
	repo := mock_domain.NewMockClientRepository(ctrl)

	repo.EXPECT().
		GetClient(gomock.Any(), "sssoctl").
		Return(wantBootstrapClient(), nil).
		Times(2)
	repo.EXPECT().CreateClient(gomock.Any(), gomock.Any()).Times(0)

	for i := 0; i < 2; i++ {
		if err := ensureBootstrapSSSOCTLClient(context.Background(), repo, zerolog.Nop()); err != nil {
			t.Fatalf("invocation %d: expected nil error, got: %v", i, err)
		}
	}
}

// TestEnsureBootstrapSSSOCTLClient_LeavesExistingClientUntouched verifies that
// an existing client with custom scopes/grants is neither overwritten nor
// mutated.
func TestEnsureBootstrapSSSOCTLClient_LeavesExistingClientUntouched(t *testing.T) {
	ctrl := gomock.NewController(t)
	repo := mock_domain.NewMockClientRepository(ctrl)

	existing := &domain.Client{
		ID:                "sssoctl",
		Name:              "customized cli client",
		Type:              domain.ClientTypeConfidential,
		IsActive:          false,
		IsConfidential:    true,
		TokenEndpointAuth: "client_secret_basic",
		AllowedGrantTypes: []string{"client_credentials"},
		AllowedScopes:     []string{"admin"},
		RequirePKCE:       true,
		RequireConsent:    true,
	}
	repo.EXPECT().GetClient(gomock.Any(), "sssoctl").Return(existing, nil)
	repo.EXPECT().CreateClient(gomock.Any(), gomock.Any()).Times(0)

	if err := ensureBootstrapSSSOCTLClient(context.Background(), repo, zerolog.Nop()); err != nil {
		t.Fatalf("expected nil error, got: %v", err)
	}
	if existing.Type != domain.ClientTypeConfidential || existing.AllowedGrantTypes[0] != "client_credentials" {
		t.Fatal("existing client was mutated by bootstrap")
	}
}

// TestEnsureBootstrapSSSOCTLClient_CreatesOnMongoNotFound verifies the real
// repository path: mongodb.ClientRepository.GetClient returns its own
// mongodb.ErrClientNotFound sentinel (mongodb/client_repository.go:20), which
// is a different error instance from domain.ErrClientNotFound. The bootstrap
// must accept it as "not found" and create the client.
func TestEnsureBootstrapSSSOCTLClient_CreatesOnMongoNotFound(t *testing.T) {
	ctrl := gomock.NewController(t)
	repo := mock_domain.NewMockClientRepository(ctrl)

	repo.EXPECT().GetClient(gomock.Any(), "sssoctl").Return(nil, mongodb.ErrClientNotFound)
	repo.EXPECT().
		CreateClient(gomock.Any(), gomock.Eq(wantBootstrapClient())).
		Return(nil).
		Times(1)

	if err := ensureBootstrapSSSOCTLClient(context.Background(), repo, zerolog.Nop()); err != nil {
		t.Fatalf("expected nil error, got: %v", err)
	}
}

// TestEnsureBootstrapSSSOCTLClient_PropagatesLookupError verifies that any
// GetClient error other than ErrClientNotFound is wrapped and returned, and
// CreateClient is never attempted.
func TestEnsureBootstrapSSSOCTLClient_PropagatesLookupError(t *testing.T) {
	ctrl := gomock.NewController(t)
	repo := mock_domain.NewMockClientRepository(ctrl)

	lookupErr := errors.New("database down")
	repo.EXPECT().GetClient(gomock.Any(), "sssoctl").Return(nil, lookupErr)
	repo.EXPECT().CreateClient(gomock.Any(), gomock.Any()).Times(0)

	err := ensureBootstrapSSSOCTLClient(context.Background(), repo, zerolog.Nop())
	if err == nil {
		t.Fatal("expected wrapped error, got nil")
	}
	if !errors.Is(err, lookupErr) {
		t.Fatalf("expected wrapped %v, got: %v", lookupErr, err)
	}
}
