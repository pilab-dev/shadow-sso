package services

import (
	"context"
	"errors"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/pilab-dev/shadow-sso/client" // Assuming mock for domain.OAuthRepository
	mock_domain "github.com/pilab-dev/shadow-sso/domain/mocks"
	ssov1 "github.com/pilab-dev/shadow-sso/gen/proto/sso/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

// MockPasswordHasher is a simple mock for PasswordHasher
type MockPasswordHasher struct {
	HashFunc   func(password string) (string, error)
	VerifyFunc func(hashedPassword, password string) error
}

func (m *MockPasswordHasher) Hash(password string) (string, error) {
	if m.HashFunc != nil {
		return m.HashFunc(password)
	}
	return "hashed-" + password, nil
}

func (m *MockPasswordHasher) Verify(hashedPassword, password string) error {
	if m.VerifyFunc != nil {
		return m.VerifyFunc(hashedPassword, password)
	}
	if hashedPassword == "hashed-"+password {
		return nil
	}
	return errors.New("password mismatch")
}

func TestClientManagementServer_RegisterClient_WithLDAPMappings(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	clientRepo := mock_domain.NewMockClientRepository(ctrl)
	mockHasher := &MockPasswordHasher{}
	service := NewClientManagementServer(clientRepo, mockHasher)

	reqMsg := &ssov1.RegisterClientRequest{
		ClientName: "Test LDAP Client",
		ClientType: ssov1.ClientTypeProto_CLIENT_TYPE_CONFIDENTIAL,
		// ... other required fields for client registration
		RedirectUris:            []string{"http://localhost/callback"},
		AllowedScopes:           []string{"openid", "profile"},
		AllowedGrantTypes:       []string{"authorization_code"},
		TokenEndpointAuthMethod: "client_secret_basic",

		// LDAP Mapping Fields from proto
		ClientLdapAttributeEmail:      "mail_ldap",
		ClientLdapAttributeFirstName:  "givenName_ldap",
		ClientLdapAttributeLastName:   "sn_ldap",
		ClientLdapAttributeGroups:     "memberOf_ldap",
		ClientLdapCustomClaimsMapping: map[string]string{"custom_dept": "departmentNumber"},
	}

	clientRepo.EXPECT().CreateClient(gomock.Any(), gomock.Any()).
		DoAndReturn(func(_ context.Context, c *client.Client) error {
			assert.Equal(t, "Test LDAP Client", c.Name)
			assert.Equal(t, client.Confidential, c.Type)
			assert.Equal(t, "mail_ldap", c.ClientLDAPAttributeEmail)
			assert.Equal(t, "givenName_ldap", c.ClientLDAPAttributeFirstName)
			assert.Equal(t, "sn_ldap", c.ClientLDAPAttributeLastName)
			assert.Equal(t, "memberOf_ldap", c.ClientLDAPAttributeGroups)
			assert.Equal(t, map[string]string{"custom_dept": "departmentNumber"}, c.ClientLDAPCustomClaimsMapping)
			assert.NotEmpty(t, c.ID)
			assert.NotEmpty(t, c.Secret) // Hashed secret
			return nil
		})

	req := connect.NewRequest(reqMsg)
	resp, err := service.RegisterClient(context.Background(), req)

	require.NoError(t, err)
	require.NotNil(t, resp.Msg)
	require.NotNil(t, resp.Msg.Client)
	assert.Equal(t, "Test LDAP Client", resp.Msg.Client.ClientName)
	assert.Equal(t, "mail_ldap", resp.Msg.Client.ClientLdapAttributeEmail)
	assert.Equal(t, "givenName_ldap", resp.Msg.Client.ClientLdapAttributeFirstName)
	assert.Equal(t, "sn_ldap", resp.Msg.Client.ClientLdapAttributeLastName)
	assert.Equal(t, "memberOf_ldap", resp.Msg.Client.ClientLdapAttributeGroups)
	assert.Equal(t, map[string]string{"custom_dept": "departmentNumber"}, resp.Msg.Client.ClientLdapCustomClaimsMapping)
	assert.NotEmpty(t, resp.Msg.Client.ClientSecret, "Plaintext secret should be in register response")
}

func TestClientManagementServer_UpdateClient_WithLDAPMappings(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	clientRepo := mock_domain.NewMockClientRepository(ctrl)
	mockHasher := &MockPasswordHasher{} // Not directly used in update for these fields, but part of service
	service := NewClientManagementServer(clientRepo, mockHasher)

	clientID := "client-123"
	existingClient := &client.Client{
		ID:                            clientID,
		Name:                          "Old Name",
		Type:                          client.Confidential,
		ClientLDAPAttributeEmail:      "old_mail",
		ClientLDAPCustomClaimsMapping: map[string]string{"old_claim": "old_attr"},
		UpdatedAt:                     time.Now().Add(-1 * time.Hour),
	}

	// For UpdateClientRequest, using direct values assuming proto fields are not pointers.
	// If proto uses wrapperspb (like *wrapperspb.StringValue), the request setup would be different.
	// The service logic currently assumes direct values or GetXxx() returning the value.
	reqMsg := &ssov1.UpdateClientRequest{
		ClientId: clientID,
		// Base fields that are usually updatable
		ClientName: "New Name",
		// LDAP Mapping fields to update
		ClientLdapAttributeEmail:     "new_mail_ldap",      // Update
		ClientLdapAttributeFirstName: "new_givenName_ldap", // Add
		// ClientLdapAttributeLastName is not in request, should remain unchanged if not handled by proto presence
		ClientLdapCustomClaimsMapping: map[string]string{"new_dept": "newDeptNum"}, // Replace map
		// ClientLdapAttributeGroups: "", // To test clearing an attribute
	}
	// To test clearing ClientLdapAttributeGroups, the proto and ssoctl need to support it.
	// If proto field is string, sending "" would clear it.
	// If proto field is *string, sending a StringValue("") vs nil matters.
	// Current service logic for UpdateClient: if req.Msg.X != "", dbClient.X = req.Msg.X
	// This means sending empty string will update to empty.

	clientRepo.EXPECT().GetClient(gomock.Any(), clientID).Return(existingClient, nil)
	clientRepo.EXPECT().UpdateClient(gomock.Any(), gomock.Any()).
		DoAndReturn(func(_ context.Context, c *client.Client) error {
			assert.Equal(t, clientID, c.ID)
			assert.Equal(t, "New Name", c.Name)
			assert.Equal(t, "new_mail_ldap", c.ClientLDAPAttributeEmail)
			assert.Equal(t, "new_givenName_ldap", c.ClientLDAPAttributeFirstName)
			assert.Empty(t, c.ClientLDAPAttributeLastName, "Lastname should be unchanged if not in req or cleared if req had empty") // Depends on proto handling
			assert.Equal(t, map[string]string{"new_dept": "newDeptNum"}, c.ClientLDAPCustomClaimsMapping)
			// assert.Empty(t, c.ClientLDAPAttributeGroups, "Groups should be cleared if req had empty string for it")
			// assert.True(t, c.UpdatedAt.After(existingClient.UpdatedAt))
			return nil
		})

	req := connect.NewRequest(reqMsg)
	resp, err := service.UpdateClient(context.Background(), req)

	require.NoError(t, err)
	require.NotNil(t, resp.Msg)
	require.NotNil(t, resp.Msg.Client)
	assert.Equal(t, "New Name", resp.Msg.Client.ClientName)
	assert.Equal(t, "new_mail_ldap", resp.Msg.Client.ClientLdapAttributeEmail)
	assert.Equal(t, "new_givenName_ldap", resp.Msg.Client.ClientLdapAttributeFirstName)
	assert.Equal(t, map[string]string{"new_dept": "newDeptNum"}, resp.Msg.Client.ClientLdapCustomClaimsMapping)
}

// Test GetClient to ensure LDAP fields are returned
func TestClientManagementServer_GetClient_ReturnsLDAPMappings(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockClientRepo := mock_domain.NewMockClientRepository(ctrl)
	service := NewClientManagementServer(mockClientRepo, &MockPasswordHasher{})

	clientID := "client-with-ldap-mappings"
	dbClient := &client.Client{
		ID:                            clientID,
		Name:                          "Mapped Client",
		Type:                          client.Confidential,
		ClientLDAPAttributeEmail:      "configured_mail_attr",
		ClientLDAPAttributeFirstName:  "configured_fn_attr",
		ClientLDAPAttributeLastName:   "configured_ln_attr",
		ClientLDAPAttributeGroups:     "configured_group_attr",
		ClientLDAPCustomClaimsMapping: map[string]string{"claim1": "ldap_attr1"},
		CreatedAt:                     time.Now(),
		UpdatedAt:                     time.Now(),
	}

	mockClientRepo.EXPECT().GetClient(gomock.Any(), clientID).Return(dbClient, nil)

	req := connect.NewRequest(&ssov1.GetClientRequest{ClientId: clientID})
	resp, err := service.GetClient(context.Background(), req)

	require.NoError(t, err)
	require.NotNil(t, resp.Msg)
	require.NotNil(t, resp.Msg.Client)
	assert.Equal(t, "configured_mail_attr", resp.Msg.Client.ClientLdapAttributeEmail)
	assert.Equal(t, "configured_fn_attr", resp.Msg.Client.ClientLdapAttributeFirstName)
	assert.Equal(t, "configured_ln_attr", resp.Msg.Client.ClientLdapAttributeLastName)
	assert.Equal(t, "configured_group_attr", resp.Msg.Client.ClientLdapAttributeGroups)
	assert.Equal(t, map[string]string{"claim1": "ldap_attr1"}, resp.Msg.Client.ClientLdapCustomClaimsMapping)
}

// TODO: Add more tests:
// - Error cases for RegisterClient and UpdateClient (e.g., validation errors, repo errors).
// - Test how UpdateClient handles partial updates for LDAP fields if proto uses optional wrappers
//   (e.g. ensuring a field is NOT updated if not present in request).
// - Test clearing/unsetting LDAP mapping fields during an update.
// - Test ListClients to ensure LDAP fields are populated in the list items.
