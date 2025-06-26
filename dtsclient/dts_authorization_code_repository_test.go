package dtsclient

import (
	"context"
	"log"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pilab-dev/ssso/apps/ssso-dts/internal/service" // DTS Service implementation
	"github.com/pilab-dev/ssso/apps/ssso-dts/internal/storage"  // DTS Storage for the service
	"github.com/pilab-dev/ssso/domain"
	dtsv1 "github.com/pilab-dev/ssso/gen/proto/dts/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
	// "google.golang.org/grpc/codes"
	// "google.golang.org/grpc/status"
)

const bufSizeClientTest = 1024 * 1024

// setupDTSClientWithBufconnServer creates a real DTS service instance (on bufconn)
// and returns a dtsclient.Client connected to it, along with the repository.
func setupDTSClientWithBufconnServer(t *testing.T) (
	repo domain.AuthorizationCodeRepository,
	dtsClient *Client,
	cleanupFunc func(),
) {
	t.Helper()
	tempDir, err := os.MkdirTemp("", "dts_client_adapter_test_")
	require.NoError(t, err)

	dbPath := filepath.Join(tempDir, "test_dts_for_client.db")
	dtsStorage, err := storage.NewBBoltStore(dbPath, 1*time.Hour, 10*time.Minute)
	require.NoError(t, err)

	listener := bufconn.Listen(bufSizeClientTest)
	s := grpc.NewServer()
	dtsServerImpl := service.NewDTSService(dtsStorage) // Actual DTS service
	dtsv1.RegisterTokenStoreServiceServer(s, dtsServerImpl)

	go func() {
		if err := s.Serve(listener); err != nil {
			log.Printf("Bufconn server exited with error: %v", err) // Use log.Printf for goroutines
		}
	}()

	dialer := func(context.Context, string) (net.Conn, error) {
		return listener.Dial()
	}

	// Create the dtsclient.Client (the one being tested for its adapters)
	dtsClient, err = NewClient(Config{
		Address:        "bufnet", // Not actually used by dialer but good for consistency
		ConnectTimeout: 5 * time.Second,
		// Custom dialer for bufconn
		// NewClient doesn't directly support custom dialer, so we setup conn manually for test
	})
	require.NoError(t, err, "Failed to create dtsclient.Client wrapper (this shouldn't fail with current NewClient)")

	// Manually replace connection for bufconn if NewClient doesn't take dial options
	// This is a bit of a hack. Ideally NewClient would accept grpc.DialOptions.
	if dtsClient.conn != nil {
		dtsClient.conn.Close() // Close the real connection it might have tried to make
	}
	conn, err := grpc.DialContext(context.Background(), "bufnet", grpc.WithContextDialer(dialer), grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	dtsClient.conn = conn
	dtsClient.DTS = dtsv1.NewTokenStoreServiceClient(conn)


	repo = NewDTSAuthorizationCodeRepository(dtsClient)
	require.NotNil(t, repo)

	cleanupFunc = func() {
		err := dtsClient.Close()
		assert.NoError(t, err, "Failed to close dtsclient.Client")
		s.GracefulStop()
		err = dtsStorage.Close()
		assert.NoError(t, err, "Failed to close BBoltStore for service")
		err = os.RemoveAll(tempDir)
		assert.NoError(t, err, "Failed to remove temp test dir for service")
	}
	return repo, dtsClient, cleanupFunc
}

func TestDTSAuthCodeRepository_SaveGetDeleteAuthCode(t *testing.T) {
	repo, _, cleanup := setupDTSClientWithBufconnServer(t)
	defer cleanup()

	ctx := context.Background()
	domainAC := &domain.AuthCode{
		Code:                "clientTestCode001",
		ClientID:            "clientTestClient",
		UserID:              "clientTestUser",
		RedirectURI:         "http://client.test/callback",
		Scope:               "openid email",
		ExpiresAt:           time.Now().Add(15 * time.Minute),
		CodeChallenge:       "clientChallenge",
		CodeChallengeMethod: "S256",
		// Used and CreatedAt are not directly stored by this adapter's current mapping
	}

	// 1. Save AuthCode
	err := repo.SaveAuthCode(ctx, domainAC)
	require.NoError(t, err, "SaveAuthCode should succeed")

	// 2. Get AuthCode
	retrievedAC, err := repo.GetAuthCode(ctx, domainAC.Code)
	require.NoError(t, err, "GetAuthCode should succeed")
	require.NotNil(t, retrievedAC, "Retrieved domain.AuthCode should not be nil")

	assert.Equal(t, domainAC.Code, retrievedAC.Code)
	assert.Equal(t, domainAC.ClientID, retrievedAC.ClientID)
	assert.Equal(t, domainAC.UserID, retrievedAC.UserID)
	assert.Equal(t, domainAC.Scope, retrievedAC.Scope)
	assert.WithinDuration(t, domainAC.ExpiresAt, retrievedAC.ExpiresAt, time.Second, "ExpiresAt mismatch")
	assert.False(t, retrievedAC.Used, "Retrieved code from DTS should not be marked 'Used'")


	// 3. Get Non-existent AuthCode
	nonExistentAC, err := repo.GetAuthCode(ctx, "nonexistentClientCode")
	require.NoError(t, err, "GetAuthCode for non-existent code should not error itself")
	assert.Nil(t, nonExistentAC, "Result for non-existent code should be nil")


	// 4. Mark As Used (Deletes)
	err = repo.MarkAuthCodeAsUsed(ctx, domainAC.Code)
	require.NoError(t, err, "MarkAuthCodeAsUsed should succeed")

	// 5. Get AuthCode after marked as used
	afterUsedAC, err := repo.GetAuthCode(ctx, domainAC.Code)
	require.NoError(t, err, "GetAuthCode after MarkAuthCodeAsUsed should not error itself")
	assert.Nil(t, afterUsedAC, "Result should be nil after code is marked as used")
}


func TestDTSAuthCodeRepository_SaveExpiredAuthCode(t *testing.T) {
	repo, _, cleanup := setupDTSClientWithBufconnServer(t)
	defer cleanup()
	ctx := context.Background()

	expiredDomainAC := &domain.AuthCode{
		Code:      "clientTestExpiredCode",
		ClientID:  "client1",
		UserID:    "user1",
		ExpiresAt: time.Now().Add(-10 * time.Minute), // Already expired
	}

	err := repo.SaveAuthCode(ctx, expiredDomainAC)
	// The DTS service's StoreAuthCode should return InvalidArgument for expired codes.
	// The adapter should propagate this.
	require.Error(t, err, "Saving an already expired auth code should result in an error")
	// Expected gRPC status error, check code if possible (depends on how error is wrapped)
	// For now, just check that an error occurs. Detailed status check would be good.
	// st, ok := status.FromError(err)
	// require.True(t, ok, "Error should be a gRPC status error")
	// assert.Equal(t, codes.InvalidArgument, st.Code())
	assert.Contains(t, err.Error(), "already expired or has invalid expiration", "Error message mismatch for expired code save")
}


func TestDTSAuthCodeRepository_DeleteExpiredAuthCodes_IsNoOp(t *testing.T) {
	repo, _, cleanup := setupDTSClientWithBufconnServer(t)
	defer cleanup()
	ctx := context.Background()

	// This method should be a no-op for DTS and not error.
	err := repo.DeleteExpiredAuthCodes(ctx)
	assert.NoError(t, err, "DeleteExpiredAuthCodes should be a no-op and not return an error for DTS adapter")
	// Add a log spy or check logs if you want to confirm it logged a message.
}

// TODO: Add tests for other adapter methods and other adapters (PKCE, DeviceAuth, TokenRepo, FlowStore, UserSessionStore)
// - Test GetAuthCode for an expired code that might still be in DTS briefly before cleanup.
// - Test interactions when the DTS service itself returns an internal error.
// - Test mapping of all fields for each adapter.
// - For stores like DTSFlowStore, test Store, Get, Update, Delete methods.This is getting quite long. I'll use `create_file_with_block` as it's a new file.
