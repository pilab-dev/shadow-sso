package services

import (
	"context"
	"testing"

	"connectrpc.com/connect"
	"github.com/pilab-dev/shadow-sso/domain"
	mock_domain "github.com/pilab-dev/shadow-sso/domain/mocks" // Assuming mocks for domain.IdPRepository are here
	ssov1 "github.com/pilab-dev/shadow-sso/gen/proto/sso/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func TestIdPManagementServer_AddIdP_LDAP_Success(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockIdPRepo := mock_domain.NewMockIdPRepository(ctrl) // Use generated mock
	service := NewIdPManagementServer(mockIdPRepo)

	ldapReqFields := &ssov1.IdentityProviderProto{ // Assuming these fields exist on the proto
		LdapServerUrl:     "ldap://localhost:389",
		LdapUserBaseDn:    "ou=users,dc=example,dc=com",
		LdapUserFilter:    "(uid=%s)",
		LdapAttrUsername:  "uid",
		LdapAttrEmail:     "mail",
		LdapAttrFirstname: "givenName",
		LdapAttrLastname:  "sn",
		LdapAttrGroups:    "memberOf",
		LdapStarttls:      true,
		LdapSkipTlsVerify: false,
		LdapBindDn:        "cn=admin,dc=example,dc=com",
		LdapBindPassword:  "secretadminpassword",
	}

	reqMsg := &ssov1.AddIdPRequest{
		Name:              "Test LDAP",
		Type:              ssov1.IdPTypeProto_IDP_TYPE_LDAP, // Assumes this enum value
		IsEnabled:         true,
		LdapServerUrl:     ldapReqFields.LdapServerUrl,
		LdapUserBaseDn:    ldapReqFields.LdapUserBaseDn,
		LdapUserFilter:    ldapReqFields.LdapUserFilter,
		LdapAttrUsername:  ldapReqFields.LdapAttrUsername,
		LdapAttrEmail:     ldapReqFields.LdapAttrEmail,
		LdapAttrFirstname: ldapReqFields.LdapAttrFirstname,
		LdapAttrLastname:  ldapReqFields.LdapAttrLastname,
		LdapAttrGroups:    ldapReqFields.LdapAttrGroups,
		LdapStarttls:      ldapReqFields.LdapStarttls,
		LdapSkipTlsVerify: ldapReqFields.LdapSkipTlsVerify,
		LdapBindDn:        ldapReqFields.LdapBindDn,
		LdapBindPassword:  ldapReqFields.LdapBindPassword,
		AttributeMappings: []*ssov1.AttributeMappingProto{},
	}

	mockIdPRepo.EXPECT().AddIdP(gomock.Any(), gomock.Any()).
		DoAndReturn(func(_ context.Context, idp *domain.IdentityProvider) error {
			assert.Equal(t, "Test LDAP", idp.Name)
			assert.Equal(t, domain.IdPTypeLDAP, idp.Type)
			assert.True(t, idp.IsEnabled)
			assert.Equal(t, ldapReqFields.LdapServerUrl, idp.LDAP.ServerURL)
			assert.Equal(t, ldapReqFields.LdapUserBaseDn, idp.LDAP.UserBaseDN)
			assert.Equal(t, ldapReqFields.LdapUserFilter, idp.LDAP.UserFilter)
			assert.Equal(t, ldapReqFields.LdapBindPassword, idp.LDAP.BindPassword) // Check if secret is passed to repo
			// ... check other LDAP fields ...
			idp.ID = "new-idp-id" // Simulate ID generation by repo or db
			return nil
		})

	req := connect.NewRequest(reqMsg)
	resp, err := service.AddIdP(context.Background(), req)

	require.NoError(t, err)
	require.NotNil(t, resp.Msg)
	require.NotNil(t, resp.Msg.Idp)
	assert.Equal(t, "Test LDAP", resp.Msg.Idp.Name)
	assert.Equal(t, ssov1.IdPTypeProto_IDP_TYPE_LDAP, resp.Msg.Idp.Type)
	assert.Equal(t, ldapReqFields.LdapServerUrl, resp.Msg.Idp.LdapServerUrl) // Check if fields are in response
	assert.Empty(t, resp.Msg.Idp.OidcClientSecret, "OIDC secret should be empty in response")
	assert.Empty(t, resp.Msg.Idp.LdapBindPassword, "LDAP bind password should be empty in response")
}

func TestIdPManagementServer_AddIdP_LDAP_MissingRequiredFields(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockIdPRepo := mock_domain.NewMockIdPRepository(ctrl)
	service := NewIdPManagementServer(mockIdPRepo)

	testCases := []struct {
		name    string
		reqMsg  *ssov1.AddIdPRequest
		wantErr connect.Code
	}{
		{
			name: "Missing LDAP Server URL",
			reqMsg: &ssov1.AddIdPRequest{
				Name: "Test LDAP", Type: ssov1.IdPTypeProto_IDP_TYPE_LDAP,
				LdapUserBaseDn: "ou=users", LdapUserFilter: "(uid=%s)",
			},
			wantErr: connect.CodeInvalidArgument,
		},
		{
			name: "Missing LDAP User Base DN",
			reqMsg: &ssov1.AddIdPRequest{
				Name: "Test LDAP", Type: ssov1.IdPTypeProto_IDP_TYPE_LDAP,
				LdapServerUrl: "ldap://host", LdapUserFilter: "(uid=%s)",
			},
			wantErr: connect.CodeInvalidArgument,
		},
		{
			name: "Missing LDAP User Filter",
			reqMsg: &ssov1.AddIdPRequest{
				Name: "Test LDAP", Type: ssov1.IdPTypeProto_IDP_TYPE_LDAP,
				LdapServerUrl: "ldap://host", LdapUserBaseDn: "ou=users",
			},
			wantErr: connect.CodeInvalidArgument,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req := connect.NewRequest(tc.reqMsg)
			_, err := service.AddIdP(context.Background(), req)
			require.Error(t, err)
			assert.Equal(t, tc.wantErr, connect.CodeOf(err))
		})
	}
}

func ToPtr[T any](t T) *T {
	return &t
}

func TestIdPManagementServer_UpdateIdP_LDAP_Success(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockIdPRepo := mock_domain.NewMockIdPRepository(ctrl)
	service := NewIdPManagementServer(mockIdPRepo)

	existingIdP := &domain.IdentityProvider{
		ID:        "ldap-id-123",
		Name:      "Old LDAP Name",
		Type:      domain.IdPTypeLDAP,
		IsEnabled: true,
		LDAP: domain.LDAPConfig{
			ServerURL:         "ldap://oldhost",
			UserBaseDN:        "ou=old,dc=example,dc=com",
			UserFilter:        "(uid=%s)",
			AttributeUsername: "uid",
		},
	}

	reqMsg := &ssov1.UpdateIdPRequest{
		Id:            "ldap-id-123",
		Name:          "New LDAP Name",         // Changed
		IsEnabled:     false,                   // Changed
		LdapServerUrl: ToPtr("ldap://newhost"), // Changed
		// LDAPUserBaseDN is not changed in this request
		LdapAttrEmail: ToPtr("newmailattribute"), // Added
	}

	mockIdPRepo.EXPECT().GetIdPByID(gomock.Any(), "ldap-id-123").Return(existingIdP, nil)
	mockIdPRepo.EXPECT().UpdateIdP(gomock.Any(), gomock.Any()).
		DoAndReturn(func(_ context.Context, idp *domain.IdentityProvider) error {
			assert.Equal(t, "ldap-id-123", idp.ID)
			assert.Equal(t, "New LDAP Name", idp.Name)
			assert.False(t, idp.IsEnabled)
			assert.Equal(t, "ldap://newhost", idp.LDAP.ServerURL)
			assert.Equal(t, "ou=old,dc=example,dc=com", idp.LDAP.UserBaseDN) // Unchanged
			assert.Equal(t, "newmailattribute", idp.LDAP.AttributeEmail)     // New field
			assert.Equal(t, "uid", idp.LDAP.AttributeUsername)               // Existing, unchanged
			return nil
		})

	req := connect.NewRequest(reqMsg)
	resp, err := service.UpdateIdP(context.Background(), req)

	require.NoError(t, err)
	require.NotNil(t, resp.Msg)
	require.NotNil(t, resp.Msg.Idp)
	assert.Equal(t, "New LDAP Name", resp.Msg.Idp.Name)
	assert.False(t, resp.Msg.Idp.IsEnabled)
	assert.Equal(t, "ldap://newhost", resp.Msg.Idp.LdapServerUrl)
	assert.Equal(t, "newmailattribute", resp.Msg.Idp.LdapAttrEmail)
}

func TestIdPManagementServer_UpdateIdP_LDAP_SetRequiredToEmpty(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockIdPRepo := mock_domain.NewMockIdPRepository(ctrl)
	service := NewIdPManagementServer(mockIdPRepo)

	existingIdP := &domain.IdentityProvider{
		ID:   "ldap-id-123",
		Name: "Test LDAP",
		Type: domain.IdPTypeLDAP,
		LDAP: domain.LDAPConfig{
			ServerURL:  "ldap://host",
			UserBaseDN: "ou=users",
			UserFilter: "(uid=%s)",
		},
	}

	reqMsg := &ssov1.UpdateIdPRequest{
		Id:            "ldap-id-123",
		LdapServerUrl: ToPtr(""), // Attempting to set required field to empty
	}

	mockIdPRepo.EXPECT().GetIdPByID(gomock.Any(), "ldap-id-123").Return(existingIdP, nil)
	// UpdateIdP should not be called if validation fails

	req := connect.NewRequest(reqMsg)
	_, err := service.UpdateIdP(context.Background(), req)
	require.Error(t, err)
	assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err))
}

// TODO: Add tests for GetIdP, ListIdPs, DeleteIdP focusing on LDAP specific aspects if any,
// primarily ensuring correct proto<->domain conversion and secret handling.
// Test cases for OIDC and SAML should also exist, these are LDAP-focused additions.
// Test secret encryption/decryption logic if/when implemented.
// Test RBAC if implemented at service layer (though interceptors are common).
