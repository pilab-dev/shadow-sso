package services

import (
	"context"
	"strings"
	"testing"

	"github.com/pilab-dev/shadow-sso/domain"
	mock_domain "github.com/pilab-dev/shadow-sso/domain/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

// TestDefaultClientService_CreateClient_HashesPlaintextSecret is a regression
// test for the production wiring: defaultClientService.CreateClient must hash a
// plaintext secret with bcrypt before persisting it, and must restore the
// plaintext on the returned client. The api/openidv2_1 test harness wires
// client.NewClientService (which already hashes); the production adapter used
// to persist the secret in plaintext, so a client registered via
// POST /oauth2/register could never authenticate against the repository's
// bcrypt comparison.
func TestDefaultClientService_CreateClient_HashesPlaintextSecret(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	clientRepo := mock_domain.NewMockClientRepository(ctrl)
	svc := newClientService(clientRepo)

	plaintext := "super-secret-client-password"
	input := &domain.Client{ID: "client-1", Name: "DCR Client", Type: domain.ClientTypeConfidential, Secret: plaintext}

	var persistedSecret string
	clientRepo.EXPECT().CreateClient(gomock.Any(), gomock.Any()).
		DoAndReturn(func(_ context.Context, c *domain.Client) error {
			// Read the secret here: client.ClientService restores the plaintext
			// on the same pointer after the store call returns.
			persistedSecret = c.Secret
			return nil
		}).Times(1)

	created, err := svc.CreateClient(context.Background(), input)
	require.NoError(t, err)

	assert.True(t, strings.HasPrefix(persistedSecret, "$2a$") || strings.HasPrefix(persistedSecret, "$2b$"),
		"secret persisted to the repository must be a bcrypt hash, got %q", persistedSecret)
	assert.NotEqual(t, plaintext, persistedSecret, "plaintext secret must not be persisted at rest")

	// client.ClientService restores the plaintext on the returned client so the
	// register endpoint can echo it to the caller.
	assert.Equal(t, plaintext, created.Secret)
}

// TestDefaultClientService_CreateClient_PreservesExistingBcryptHash asserts the
// isBcryptHash guard: an already-hashed secret is persisted unchanged.
func TestDefaultClientService_CreateClient_PreservesExistingBcryptHash(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	clientRepo := mock_domain.NewMockClientRepository(ctrl)
	svc := newClientService(clientRepo)

	hashed := "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy"
	input := &domain.Client{ID: "client-2", Name: "Existing", Secret: hashed}

	clientRepo.EXPECT().CreateClient(gomock.Any(), gomock.Any()).
		DoAndReturn(func(_ context.Context, c *domain.Client) error {
			assert.Equal(t, hashed, c.Secret, "already-hashed secret must be persisted unchanged")
			return nil
		}).Times(1)

	created, err := svc.CreateClient(context.Background(), input)
	require.NoError(t, err)
	assert.Equal(t, hashed, created.Secret)
}
