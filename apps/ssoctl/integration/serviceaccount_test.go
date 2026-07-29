package integration

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"connectrpc.com/connect"
	ssov1 "github.com/pilab-dev/shadow-sso/gen/proto/sso/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCLIServiceAccount_CreateKey verifies that creating a SA key returns valid
// JSON with the expected fields.
func TestCLIServiceAccount_CreateKey(t *testing.T) {
	h := SetupCLITest(t)
	if h == nil {
		return
	}
	defer StopCLITest(t, h)

	resp, err := h.SAClient.CreateServiceAccountKey(context.Background(), connect.NewRequest(
		&ssov1.CreateServiceAccountKeyRequest{
			ProjectId:   "test-project",
			DisplayName: "Test SA",
		},
	))
	require.NoError(t, err, "CreateServiceAccountKey failed")
	require.NotNil(t, resp.Msg, "response message is nil")
	require.NotNil(t, resp.Msg.Key, "response key is nil")

	key := resp.Msg.Key

	// Verify required fields exist and are meaningful
	assert.NotEmpty(t, key.GetType(), "type field is empty")
	assert.Equal(t, "test-project", key.GetProjectId(), "project_id mismatch")
	assert.NotEmpty(t, key.GetPrivateKeyId(), "private_key_id is empty")
	assert.True(t, strings.Contains(key.GetPrivateKey(), "RSA PRIVATE KEY"),
		"private_key should be an RSA private key PEM block")
	assert.NotEmpty(t, key.GetClientEmail(), "client_email is empty")

	// Verify the service account ID is returned
	assert.NotEmpty(t, resp.Msg.GetServiceAccountId(), "service_account_id is empty")

	// Simulate what the CLI does: marshal the key output to JSON and validate the shape
	keyOutput := map[string]string{
		"type":                        key.GetType(),
		"project_id":                  key.GetProjectId(),
		"private_key_id":              key.GetPrivateKeyId(),
		"private_key":                 key.GetPrivateKey(),
		"client_email":                key.GetClientEmail(),
		"client_id":                   key.GetClientId(),
		"auth_uri":                    key.GetAuthUri(),
		"token_uri":                   key.GetTokenUri(),
		"auth_provider_x509_cert_url": key.GetAuthProviderX509CertUrl(),
		"client_x509_cert_url":        key.GetClientX509CertUrl(),
	}
	jsonBytes, err := json.MarshalIndent(keyOutput, "", "  ")
	require.NoError(t, err, "failed to marshal key to JSON")

	var parsed map[string]interface{}
	err = json.Unmarshal(jsonBytes, &parsed)
	require.NoError(t, err, "output is not valid JSON")

	// Verify all expected keys are present in the JSON
	expectedKeys := []string{
		"type", "project_id", "private_key_id", "private_key",
		"client_email", "client_id", "auth_uri", "token_uri",
		"auth_provider_x509_cert_url", "client_x509_cert_url",
	}
	for _, k := range expectedKeys {
		_, ok := parsed[k]
		assert.True(t, ok, "JSON output missing key: %s", k)
	}
}

// TestCLIServiceAccount_ListKeys verifies that listing SA keys works after
// creating a key.
func TestCLIServiceAccount_ListKeys(t *testing.T) {
	h := SetupCLITest(t)
	if h == nil {
		return
	}
	defer StopCLITest(t, h)

	// First, create a key so we have something to list
	createResp, err := h.SAClient.CreateServiceAccountKey(context.Background(), connect.NewRequest(
		&ssov1.CreateServiceAccountKeyRequest{
			ProjectId:   "test-project",
			DisplayName: "List Test SA",
		},
	))
	require.NoError(t, err, "CreateServiceAccountKey failed")
	saID := createResp.Msg.GetServiceAccountId()
	require.NotEmpty(t, saID, "service account ID should not be empty")

	// List keys for the service account
	listResp, err := h.SAClient.ListServiceAccountKeys(context.Background(), connect.NewRequest(
		&ssov1.ListServiceAccountKeysRequest{
			ServiceAccountId: saID,
		},
	))
	require.NoError(t, err, "ListServiceAccountKeys failed")
	require.NotNil(t, listResp.Msg, "response message is nil")

	keys := listResp.Msg.GetKeys()
	assert.NotEmpty(t, keys, "should have at least one key after creation")
	if len(keys) > 0 {
		assert.NotEmpty(t, keys[0].GetKeyId(), "key_id should not be empty")
		assert.Equal(t, saID, keys[0].GetServiceAccountId(), "service_account_id mismatch")
		assert.NotEmpty(t, keys[0].GetAlgorithm(), "algorithm should not be empty")
		assert.NotEmpty(t, keys[0].GetStatus(), "status should not be empty")
	}
}

// TestCLIServiceAccount_DeleteKey verifies that deleting a SA key succeeds
// and is idempotent (can be called more than once for the same key).
func TestCLIServiceAccount_DeleteKey(t *testing.T) {
	h := SetupCLITest(t)
	if h == nil {
		return
	}
	defer StopCLITest(t, h)

	// Create a key to delete
	createResp, err := h.SAClient.CreateServiceAccountKey(context.Background(), connect.NewRequest(
		&ssov1.CreateServiceAccountKeyRequest{
			ProjectId:   "test-project",
			DisplayName: "Delete Test SA",
		},
	))
	require.NoError(t, err, "CreateServiceAccountKey failed")
	saID := createResp.Msg.GetServiceAccountId()
	keyID := createResp.Msg.GetKey().GetPrivateKeyId()
	require.NotEmpty(t, saID, "service account ID should not be empty")
	require.NotEmpty(t, keyID, "key ID should not be empty")

	// Delete the key
	_, err = h.SAClient.DeleteServiceAccountKey(context.Background(), connect.NewRequest(
		&ssov1.DeleteServiceAccountKeyRequest{
			ServiceAccountId: saID,
			KeyId:            keyID,
		},
	))
	require.NoError(t, err, "first DeleteServiceAccountKey should succeed")

	// Delete again — the implementation marks as REVOKED, so second call should
	// also succeed (idempotent via status update).
	_, err = h.SAClient.DeleteServiceAccountKey(context.Background(), connect.NewRequest(
		&ssov1.DeleteServiceAccountKeyRequest{
			ServiceAccountId: saID,
			KeyId:            keyID,
		},
	))
	require.NoError(t, err, "second DeleteServiceAccountKey should be idempotent")
}

// TestCLIServiceAccount_CreateKey_MissingProject verifies that omitting the
// required project-id flag returns an InvalidArgument error.
func TestCLIServiceAccount_CreateKey_MissingProject(t *testing.T) {
	h := SetupCLITest(t)
	if h == nil {
		return
	}
	defer StopCLITest(t, h)

	_, err := h.SAClient.CreateServiceAccountKey(context.Background(), connect.NewRequest(
		&ssov1.CreateServiceAccountKeyRequest{
			// ProjectId intentionally left empty
			DisplayName: "Missing Project SA",
		},
	))
	require.Error(t, err, "expected error for missing project_id")
	assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err),
		"expected InvalidArgument, got %s", connect.CodeOf(err))
}
