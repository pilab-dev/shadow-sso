package integration

import (
	"context"
	"testing"

	"connectrpc.com/connect"
	ssov1 "github.com/pilab-dev/shadow-sso/gen/proto/sso/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ptr returns a pointer to s.
func ptr(s string) *string { return &s }

// TestCLIIdP_Add_OIDC verifies that adding an OIDC identity provider succeeds
// and returns the IdP with correct field values.
func TestCLIIdP_Add_OIDC(t *testing.T) {
	h := SetupCLITest(t)
	if h == nil {
		return
	}
	defer StopCLITest(t, h)

	resp, err := h.IdPClient.AddIdP(context.Background(), connect.NewRequest(
		&ssov1.AddIdPRequest{
			Name:      "test-oidc",
			Type:      ssov1.IdPTypeProto_IDP_TYPE_OIDC,
			IsEnabled: true,
			OidcClientId:  ptr("test-client-id"),
			OidcIssuerUrl: ptr("https://accounts.google.com"),
		},
	))
	require.NoError(t, err, "AddIdP failed")
	require.NotNil(t, resp.Msg, "response message is nil")
	require.NotNil(t, resp.Msg.Idp, "IdP in response is nil")

	idp := resp.Msg.Idp

	assert.NotEmpty(t, idp.GetId(), "IdP ID should be generated")
	assert.Equal(t, "test-oidc", idp.GetName(), "IdP name mismatch")
	assert.Equal(t, ssov1.IdPTypeProto_IDP_TYPE_OIDC, idp.GetType(), "IdP type mismatch")
	assert.True(t, idp.GetIsEnabled(), "IdP should be enabled")

	// Verify OIDC fields
	assert.Equal(t, "test-client-id", idp.GetOidcClientId(), "oidc_client_id mismatch")
	assert.Equal(t, "https://accounts.google.com", idp.GetOidcIssuerUrl(), "oidc_issuer_url mismatch")

	// OIDC client secret should NOT be returned in response
	assert.Empty(t, idp.GetOidcClientSecret(), "oidc_client_secret should be empty in response")

	// Verify timestamps are set
	assert.NotNil(t, idp.GetCreatedAt(), "created_at should be set")
	assert.NotNil(t, idp.GetUpdatedAt(), "updated_at should be set")
}

// TestCLIIdP_Get verifies that getting an IdP by ID returns the expected
// configuration.
func TestCLIIdP_Get(t *testing.T) {
	h := SetupCLITest(t)
	if h == nil {
		return
	}
	defer StopCLITest(t, h)

	// Create an IdP first
	addResp, err := h.IdPClient.AddIdP(context.Background(), connect.NewRequest(
		&ssov1.AddIdPRequest{
			Name:      "get-test-idp",
			Type:      ssov1.IdPTypeProto_IDP_TYPE_OIDC,
			IsEnabled: true,
			OidcClientId:  ptr("get-client-id"),
			OidcIssuerUrl: ptr("https://get.example.com"),
		},
	))
	require.NoError(t, err, "AddIdP failed")
	idpID := addResp.Msg.Idp.GetId()
	require.NotEmpty(t, idpID, "IdP ID should not be empty")

	// Get the IdP by ID
	getResp, err := h.IdPClient.GetIdP(context.Background(), connect.NewRequest(
		&ssov1.GetIdPRequest{Id: idpID},
	))
	require.NoError(t, err, "GetIdP failed")
	require.NotNil(t, getResp.Msg, "response message is nil")
	require.NotNil(t, getResp.Msg.Idp, "IdP in response is nil")

	idp := getResp.Msg.Idp
	assert.Equal(t, idpID, idp.GetId(), "IdP ID mismatch")
	assert.Equal(t, "get-test-idp", idp.GetName(), "IdP name mismatch")
	assert.Equal(t, "get-client-id", idp.GetOidcClientId(), "oidc_client_id mismatch")
	assert.Equal(t, "https://get.example.com", idp.GetOidcIssuerUrl(), "oidc_issuer_url mismatch")
	assert.Empty(t, idp.GetOidcClientSecret(), "secret should be empty in get response")
}

// TestCLIIdP_List verifies that listing IdPs returns all created IdPs.
func TestCLIIdP_List(t *testing.T) {
	h := SetupCLITest(t)
	if h == nil {
		return
	}
	defer StopCLITest(t, h)

	// Create two IdPs
	for i, name := range []string{"list-idp-1", "list-idp-2"} {
		_, err := h.IdPClient.AddIdP(context.Background(), connect.NewRequest(
			&ssov1.AddIdPRequest{
				Name:          name,
				Type:          ssov1.IdPTypeProto_IDP_TYPE_OIDC,
				IsEnabled:     i == 0, // first enabled, second disabled
				OidcClientId:  ptr("list-client-" + name),
				OidcIssuerUrl: ptr("https://" + name + ".example.com"),
			},
		))
		require.NoError(t, err, "AddIdP failed for "+name)
	}

	// List all IdPs
	listResp, err := h.IdPClient.ListIdPs(context.Background(), connect.NewRequest(
		&ssov1.ListIdPsRequest{OnlyEnabled: false},
	))
	require.NoError(t, err, "ListIdPs failed")
	require.NotNil(t, listResp.Msg, "response message is nil")

	idps := listResp.Msg.GetIdps()
	assert.GreaterOrEqual(t, len(idps), 2, "should have at least 2 IdPs")

	// List only enabled
	enabledResp, err := h.IdPClient.ListIdPs(context.Background(), connect.NewRequest(
		&ssov1.ListIdPsRequest{OnlyEnabled: true},
	))
	require.NoError(t, err, "ListIdPs (only enabled) failed")
	foundDisabled := false
	for _, idp := range enabledResp.Msg.GetIdps() {
		assert.True(t, idp.GetIsEnabled(), "only-enabled list should contain only enabled IdPs, got disabled: %s", idp.GetName())
		if !idp.GetIsEnabled() {
			foundDisabled = true
		}
	}
	assert.False(t, foundDisabled, "disabled IdPs should not appear when OnlyEnabled=true")
}

// TestCLIIdP_Update verifies that updating an IdP configuration works correctly.
func TestCLIIdP_Update(t *testing.T) {
	h := SetupCLITest(t)
	if h == nil {
		return
	}
	defer StopCLITest(t, h)

	// Create an IdP to update
	addResp, err := h.IdPClient.AddIdP(context.Background(), connect.NewRequest(
		&ssov1.AddIdPRequest{
			Name:          "original-idp",
			Type:          ssov1.IdPTypeProto_IDP_TYPE_OIDC,
			IsEnabled:     true,
			OidcClientId:  ptr("original-client"),
			OidcIssuerUrl: ptr("https://original.example.com"),
		},
	))
	require.NoError(t, err, "AddIdP failed")
	idpID := addResp.Msg.Idp.GetId()

	// Update name and disable
	updateResp, err := h.IdPClient.UpdateIdP(context.Background(), connect.NewRequest(
		&ssov1.UpdateIdPRequest{
			Id:        idpID,
			Name:      "updated-idp",
			IsEnabled: false,
		},
	))
	require.NoError(t, err, "UpdateIdP failed")
	require.NotNil(t, updateResp.Msg, "response message is nil")
	require.NotNil(t, updateResp.Msg.Idp, "IdP in response is nil")

	idp := updateResp.Msg.Idp
	assert.Equal(t, idpID, idp.GetId(), "IdP ID mismatch")
	assert.Equal(t, "updated-idp", idp.GetName(), "name was not updated")
	assert.False(t, idp.GetIsEnabled(), "is_enabled was not updated to false")

	// Verify original fields are preserved
	assert.Equal(t, "original-client", idp.GetOidcClientId(), "oidc_client_id should be preserved")
	assert.Equal(t, "https://original.example.com", idp.GetOidcIssuerUrl(), "oidc_issuer_url should be preserved")
}

// TestCLIIdP_Delete verifies that deleting an IdP succeeds and subsequent
// GetIdP returns NotFound.
func TestCLIIdP_Delete(t *testing.T) {
	h := SetupCLITest(t)
	if h == nil {
		return
	}
	defer StopCLITest(t, h)

	// Create an IdP to delete
	addResp, err := h.IdPClient.AddIdP(context.Background(), connect.NewRequest(
		&ssov1.AddIdPRequest{
			Name:          "delete-me",
			Type:          ssov1.IdPTypeProto_IDP_TYPE_OIDC,
			IsEnabled:     true,
			OidcClientId:  ptr("delete-client"),
			OidcIssuerUrl: ptr("https://delete.example.com"),
		},
	))
	require.NoError(t, err, "AddIdP failed")
	idpID := addResp.Msg.Idp.GetId()

	// Delete the IdP
	_, err = h.IdPClient.DeleteIdP(context.Background(), connect.NewRequest(
		&ssov1.DeleteIdPRequest{Id: idpID},
	))
	require.NoError(t, err, "DeleteIdP failed")

	// Verify it's gone
	_, err = h.IdPClient.GetIdP(context.Background(), connect.NewRequest(
		&ssov1.GetIdPRequest{Id: idpID},
	))
	require.Error(t, err, "GetIdP should fail after delete")
	assert.Equal(t, connect.CodeNotFound, connect.CodeOf(err),
		"expected NotFound after delete, got %s", connect.CodeOf(err))
}

// TestCLIIdP_Add_OIDC_MissingFields verifies that missing required OIDC fields
// (issuer URL or client ID) returns InvalidArgument.
func TestCLIIdP_Add_OIDC_MissingFields(t *testing.T) {
	h := SetupCLITest(t)
	if h == nil {
		return
	}
	defer StopCLITest(t, h)

	// Missing issuer URL
	_, err := h.IdPClient.AddIdP(context.Background(), connect.NewRequest(
		&ssov1.AddIdPRequest{
			Name:         "missing-issuer",
			Type:         ssov1.IdPTypeProto_IDP_TYPE_OIDC,
			IsEnabled:    true,
			OidcClientId: ptr("test-client-id"),
			// OidcIssuerUrl intentionally omitted
		},
	))
	require.Error(t, err, "expected error when OIDC issuer URL is missing")
	assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err),
		"expected InvalidArgument for missing issuer URL, got %s", connect.CodeOf(err))

	// Missing client ID
	_, err = h.IdPClient.AddIdP(context.Background(), connect.NewRequest(
		&ssov1.AddIdPRequest{
			Name:      "missing-client-id",
			Type:      ssov1.IdPTypeProto_IDP_TYPE_OIDC,
			IsEnabled: true,
			OidcIssuerUrl: ptr("https://accounts.google.com"),
			// OidcClientId intentionally omitted
		},
	))
	require.Error(t, err, "expected error when OIDC client ID is missing")
	assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err),
		"expected InvalidArgument for missing client ID, got %s", connect.CodeOf(err))
}
