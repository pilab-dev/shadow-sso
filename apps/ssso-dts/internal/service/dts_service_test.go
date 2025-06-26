package service

import (
	"context"
	"errors"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/pilab-dev/shadow-sso/apps/ssso-dts/internal/storage"
	dtsv1 "github.com/pilab-dev/shadow-sso/gen/proto/dts/v1"
	"github.com/pilab-dev/shadow-sso/gen/proto/dts/v1/dtsv1connect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const bufSize = 1024 * 1024

var (
	lis         *bufconn.Listener
	dtsStorage  *storage.BBoltStore
	tempTestDir string
)

// setupBufconnServer starts the gRPC server on a bufconn listener
// and initializes the storage backend for tests.
func setupBufconnServer(t *testing.T) (client dtsv1connect.TokenStoreServiceClient, cleanupFunc func()) {
	t.Helper()
	var err error
	tempTestDir, err = os.MkdirTemp("", "dts_service_test_")
	require.NoError(t, err)

	dbPath := filepath.Join(tempTestDir, "test_dts_service.db")
	dtsStorage, err = storage.NewBBoltStore(dbPath, 1*time.Hour, 10*time.Minute)
	require.NoError(t, err)
	// dtsStorage.StartCleanupRoutine(storage.KnownBuckets()) // Not strictly needed for these tests

	lis = bufconn.Listen(bufSize)
	dtsServer := NewDTSService(dtsStorage)
	path, handler := dtsv1connect.NewTokenStoreServiceHandler(dtsServer)
	mux := http.NewServeMux()
	mux.Handle(path, handler)

	go func() {
		if err := http.Serve(lis, mux); err != nil {
			log.Printf("Bufconn server exited with error: %v", err)
		}
	}()

	hc := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return lis.DialContext(ctx)
			},
		},
	}

	client = dtsv1connect.NewTokenStoreServiceClient(
		hc,
		"http://"+lis.Addr().String(),
		connect.WithGRPC(),
	)

	cleanupFunc = func() {
		err = dtsStorage.Close()
		assert.NoError(t, err, "Failed to close BBoltStore")
		err = os.RemoveAll(tempTestDir)
		assert.NoError(t, err, "Failed to remove temp test dir")
		err := lis.Close()
		assert.NoError(t, err, "Failed to close listener connection")
	}

	return client, cleanupFunc
}

func TestDTSService_AuthCode_StoreGetDelete(t *testing.T) {
	client, cleanup := setupBufconnServer(t)
	defer cleanup()

	ctx := context.Background()
	now := time.Now()
	expiresAtProto := timestamppb.New(now.Add(10 * time.Minute))

	authCode := &dtsv1.AuthCode{
		Code:                "testcode123",
		ClientId:            "testclient",
		UserId:              "testuser",
		RedirectUri:         "http://localhost/callback",
		Scope:               "openid profile",
		CodeChallenge:       "challenge",
		CodeChallengeMethod: "S256",
		ExpiresAt:           expiresAtProto,
	}

	// 1. Store AuthCode
	_, err := client.StoreAuthCode(ctx, connect.NewRequest(&dtsv1.StoreAuthCodeRequest{
		AuthCode: authCode,
	}))
	require.NoError(t, err, "StoreAuthCode should succeed")

	// 2. Get AuthCode
	getReq := connect.NewRequest(&dtsv1.GetAuthCodeRequest{Code: authCode.Code})
	retrievedAC, err := client.GetAuthCode(ctx, getReq)
	require.NoError(t, err, "GetAuthCode should succeed")
	require.NotNil(t, retrievedAC, "Retrieved AuthCode should not be nil")

	assert.Equal(t, authCode.Code, retrievedAC.Msg.Code)
	assert.Equal(t, authCode.ClientId, retrievedAC.Msg.ClientId)
	assert.Equal(t, authCode.UserId, retrievedAC.Msg.UserId)
	assert.Equal(t, authCode.Scope, retrievedAC.Msg.Scope)
	// For timestamps, allow a small delta due to potential precision differences if not using direct comparison
	assert.Equal(t, authCode.ExpiresAt.Seconds, retrievedAC.Msg.ExpiresAt.Seconds)

	// 3. Get Non-existent AuthCode
	_, err = client.GetAuthCode(ctx, connect.NewRequest(&dtsv1.GetAuthCodeRequest{Code: "nonexistentcode"}))
	require.Error(t, err, "GetAuthCode for non-existent code should fail")
	connectErr := new(connect.Error)
	ok := errors.As(err, &connectErr)
	require.True(t, ok, "Error should be a gRPC status error")
	assert.Equal(t, connect.CodeNotFound, connect.CodeOf(connectErr), "Error code should be NotFound")

	// 4. Delete AuthCode
	_, err = client.DeleteAuthCode(ctx, connect.NewRequest(&dtsv1.DeleteAuthCodeRequest{Code: authCode.Code}))
	require.NoError(t, err, "DeleteAuthCode should succeed")

	// 5. Get AuthCode after delete
	_, err = client.GetAuthCode(ctx, getReq) // Use the same getReq
	require.Error(t, err, "GetAuthCode after delete should fail")
	okDel := errors.As(err, &connectErr)
	require.True(t, okDel)
	assert.Equal(t, connect.CodeNotFound, connect.CodeOf(connectErr), "Error code should be NotFound")
}

func TestDTSService_AuthCode_StoreExpired(t *testing.T) {
	client, cleanup := setupBufconnServer(t)
	defer cleanup()
	ctx := context.Background()

	expiredAuthCode := &dtsv1.AuthCode{
		Code:      "expiredTestCode",
		ClientId:  "client1",
		UserId:    "user1",
		ExpiresAt: timestamppb.New(time.Now().Add(-5 * time.Minute)), // Already expired
	}
	_, err := client.StoreAuthCode(ctx, connect.NewRequest(&dtsv1.StoreAuthCodeRequest{AuthCode: expiredAuthCode}))
	require.Error(t, err, "Storing an already expired auth code should fail with InvalidArgument")

	connectErr := new(connect.Error)
	ok := errors.As(err, &connectErr)
	require.True(t, ok)
	assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(connectErr), "Error code should be CodeInvalidArgument")
}

func TestDTSService_GenericSetGetDelete(t *testing.T) {
	client, cleanup := setupBufconnServer(t)
	defer cleanup()
	ctx := context.Background()

	bucket := "generic_bucket"
	key := "generic_key"
	value := []byte("generic_value_data")
	ttl := 5 * time.Minute // Using time.Duration for SetRequest's TTL

	// 1. Set
	_, err := client.Set(ctx, connect.NewRequest(&dtsv1.SetRequest{
		Bucket: bucket,
		Key:    key,
		Value:  value,
		Ttl:    durationpb.New(ttl),
	}))
	require.NoError(t, err, "Generic Set operation failed")

	req2 := connect.NewRequest(&dtsv1.GetRequest{
		Bucket: bucket,
		Key:    key,
	})

	// 2. Get
	res2, err := client.Get(ctx, req2)
	require.NoError(t, err, "Generic Get operation failed")
	require.True(t, res2.Msg.Found, "Generic Get: item should be found")
	assert.Equal(t, value, res2.Msg.Value, "Generic Get: value mismatch")
	assert.True(t, res2.Msg.ExpiresAt.IsValid())
	assert.WithinDuration(t, time.Now().Add(ttl), res2.Msg.ExpiresAt.AsTime(), 1*time.Second)

	// 3. Delete
	req3 := connect.NewRequest(&dtsv1.DeleteRequest{
		Bucket: bucket,
		Key:    key,
	})
	_, err = client.Delete(ctx, req3)
	require.NoError(t, err, "Generic Delete operation failed")

	// 4. Get after delete
	req4 := connect.NewRequest(&dtsv1.GetRequest{
		Bucket: bucket,
		Key:    key,
	})
	getResponseAfterDelete, err := client.Get(ctx, req4)
	require.NoError(t, err, "Generic Get after delete failed") // Get itself doesn't error for not found
	assert.False(t, getResponseAfterDelete.Msg.Found, "Generic Get: item should not be found after delete")
}

// TODO: Add more tests for other specialized types (RefreshToken, OIDCFlw, etc.)
// and edge cases (e.g., empty keys/values for generic ops, invalid arguments).
// Test for UpdateOIDCFlw, UpdateDeviceAuth.
// Test TTL behavior for specialized types through their Get methods.
// Test GetDeviceAuthByDeviceCode vs GetDeviceAuthByUserCode.
// Test DeleteDeviceAuth and its effect on both device_code and user_code lookups.
// Test PKCE state operations.
// Test UserSession operations.
// Test AccessTokenMetadata operations.
// Test behavior when store returns errors (e.g., disk full - harder to simulate here).
