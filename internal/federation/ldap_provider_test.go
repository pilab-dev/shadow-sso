package federation_test

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/go-ldap/ldap/v3"
	"github.com/pilab-dev/shadow-sso/domain"
	"github.com/pilab-dev/shadow-sso/internal/federation"
	mock_federation "github.com/pilab-dev/shadow-sso/internal/federation/mock" // Corrected import path
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func TestLDAPProvider_AuthenticateAndFetchUser_AdminBindSuccess(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockLDAPClient := mock_federation.NewMockLDAPClient(ctrl) // Use the correct package alias

	idpConfig := &domain.IdentityProvider{
		Name: "test-ldap",
		Type: domain.IdPTypeLDAP,
		LDAP: domain.LDAPConfig{
			ServerURL:          "ldap://localhost:389",
			BindDN:             "cn=admin,dc=example,dc=com",
			BindPassword:       "adminpass",
			UserBaseDN:         "ou=users,dc=example,dc=com",
			UserFilter:         "(uid=%s)",
			AttributeEmail:     "mail",
			AttributeFirstName: "givenName",
			AttributeLastName:  "sn",
			AttributeUsername:  "uid",
			AttributeGroups:    "memberOf",
		},
	}

	provider, err := federation.NewLDAPProvider(idpConfig, mockLDAPClient)
	require.NoError(t, err)

	username := "testuser"
	password := "userpass"
	userDN := "uid=testuser,ou=users,dc=example,dc=com"
	expectedUserEntry := &ldap.Entry{
		DN: userDN,
		Attributes: []*ldap.EntryAttribute{
			{Name: "uid", Values: []string{username}},
			{Name: "mail", Values: []string{"testuser@example.com"}},
			{Name: "givenName", Values: []string{"Test"}},
			{Name: "sn", Values: []string{"User"}},
			{Name: "memberOf", Values: []string{"cn=group1,ou=groups,dc=example,dc=com"}},
		},
	}

	// Expectations
	mockLDAPClient.EXPECT().Connect(idpConfig.LDAP.ServerURL, idpConfig.LDAP.StartTLS, idpConfig.LDAP.SkipTLSVerify).Return(nil)
	mockLDAPClient.EXPECT().Bind(idpConfig.LDAP.BindDN, idpConfig.LDAP.BindPassword).Return(nil)
	mockLDAPClient.EXPECT().SearchUser(
		idpConfig.LDAP.UserBaseDN,
		fmt.Sprintf(idpConfig.LDAP.UserFilter, username),
		gomock.Any(), // Using Any for attributes list for simplicity in this test
	).Return(expectedUserEntry, nil)
	mockLDAPClient.EXPECT().Bind(userDN, password).Return(nil)
	mockLDAPClient.EXPECT().Close().Times(1)

	externalUser, err := provider.AuthenticateAndFetchUser(context.Background(), username, password)

	require.NoError(t, err)
	require.NotNil(t, externalUser)
	assert.Equal(t, userDN, externalUser.ProviderUserID)
	assert.Equal(t, "testuser@example.com", externalUser.Email)
	assert.Equal(t, "Test", externalUser.FirstName)
	assert.Equal(t, "User", externalUser.LastName)
	assert.Equal(t, username, externalUser.Username)
	assert.Equal(t, "testuser@example.com", externalUser.RawData["mail"])
	assert.Equal(t, "cn=group1,ou=groups,dc=example,dc=com", externalUser.RawData["memberOf"])
}

func TestLDAPProvider_AuthenticateAndFetchUser_DirectBindSuccess_NoAdminBind(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockLDAPClient := mock_federation.NewMockLDAPClient(ctrl)

	idpConfig := &domain.IdentityProvider{
		Name: "test-ldap-direct",
		Type: domain.IdPTypeLDAP,
		LDAP: domain.LDAPConfig{
			ServerURL:         "ldap://localhost:389",
			UserBaseDN:        "ou=users,dc=example,dc=com",
			UserFilter:        "(userPrincipalName=%s)", // User logs in with UPN
			AttributeEmail:    "mail",
			AttributeUsername: "userPrincipalName",
			// No LDAPBindDN or LDAPBindPassword
		},
	}
	provider, err := federation.NewLDAPProvider(idpConfig, mockLDAPClient)
	require.NoError(t, err)

	username := "testuser@example.com" // UPN
	password := "userpass"
	userDN := "CN=Test User,OU=Users,DC=example,DC=com"
	expectedUserEntry := &ldap.Entry{
		DN: userDN,
		Attributes: []*ldap.EntryAttribute{
			{Name: "userPrincipalName", Values: []string{username}},
			{Name: "mail", Values: []string{username}}, // mail might be same as UPN
		},
	}

	// Expectations
	mockLDAPClient.EXPECT().Connect(idpConfig.LDAP.ServerURL, idpConfig.LDAP.StartTLS, idpConfig.LDAP.SkipTLSVerify).Return(nil)
	// First bind attempt with username directly
	mockLDAPClient.EXPECT().Bind(username, password).Return(nil)
	// Search after successful direct bind
	mockLDAPClient.EXPECT().SearchUser(
		idpConfig.LDAP.UserBaseDN,
		fmt.Sprintf(idpConfig.LDAP.UserFilter, username),
		gomock.Any(),
	).Return(expectedUserEntry, nil)
	mockLDAPClient.EXPECT().Close().Times(1)

	externalUser, err := provider.AuthenticateAndFetchUser(context.Background(), username, password)

	require.NoError(t, err)
	require.NotNil(t, externalUser)
	assert.Equal(t, userDN, externalUser.ProviderUserID)
	assert.Equal(t, username, externalUser.Email)
	assert.Equal(t, username, externalUser.Username)
}

func TestLDAPProvider_AuthenticateAndFetchUser_AnonymousSearch_ThenBindSuccess(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockLDAPClient := mock_federation.NewMockLDAPClient(ctrl)

	idpConfig := &domain.IdentityProvider{
		Name: "test-ldap-anon-search",
		Type: domain.IdPTypeLDAP,
		LDAP: domain.LDAPConfig{
			ServerURL:         "ldap://localhost:389",
			UserBaseDN:        "ou=users,dc=example,dc=com",
			UserFilter:        "(uid=%s)",
			AttributeEmail:    "mail",
			AttributeUsername: "uid",
			// No LDAPBindDN or LDAPBindPassword
		},
	}
	provider, err := federation.NewLDAPProvider(idpConfig, mockLDAPClient)
	require.NoError(t, err)

	username := "searchuser"
	password := "userpass"
	userDN := "uid=searchuser,ou=users,dc=example,dc=com"
	expectedUserEntry := &ldap.Entry{
		DN: userDN,
		Attributes: []*ldap.EntryAttribute{
			{Name: "uid", Values: []string{username}},
			{Name: "mail", Values: []string{"searchuser@example.com"}},
		},
	}

	// Expectations
	mockLDAPClient.EXPECT().Connect(idpConfig.LDAP.ServerURL, idpConfig.LDAP.StartTLS, idpConfig.LDAP.SkipTLSVerify).Return(nil)
	// 1. Direct bind with username fails (e.g. server doesn't allow uid for bind, only full DN)
	mockLDAPClient.EXPECT().Bind(username, password).Return(ldap.NewError(ldap.LDAPResultInvalidDNSyntax, fmt.Errorf("invalid DN syntax for bind")))
	// 2. Anonymous bind for searching succeeds
	mockLDAPClient.EXPECT().Bind("", "").Return(nil)
	// 3. Search user anonymously
	mockLDAPClient.EXPECT().SearchUser(
		idpConfig.LDAP.UserBaseDN,
		fmt.Sprintf(idpConfig.LDAP.UserFilter, username),
		gomock.Any(),
	).Return(expectedUserEntry, nil)
	// 4. Bind as the found user DN
	mockLDAPClient.EXPECT().Bind(userDN, password).Return(nil)
	mockLDAPClient.EXPECT().Close().Times(1)

	externalUser, err := provider.AuthenticateAndFetchUser(context.Background(), username, password)

	require.NoError(t, err)
	require.NotNil(t, externalUser)
	assert.Equal(t, userDN, externalUser.ProviderUserID)
	assert.Equal(t, "searchuser@example.com", externalUser.Email)
}

func TestLDAPProvider_AuthenticateAndFetchUser_InvalidCredentials(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockLDAPClient := mock_federation.NewMockLDAPClient(ctrl)
	idpConfig := &domain.IdentityProvider{
		Name: "test-ldap", Type: domain.IdPTypeLDAP,
		LDAP: domain.LDAPConfig{
			ServerURL:    "ldap://localhost",
			BindDN:       "cn=admin",
			BindPassword: "adminpass",
			UserBaseDN:   "ou=users",
			UserFilter:   "(uid=%s)",
		},
	}
	provider, _ := federation.NewLDAPProvider(idpConfig, mockLDAPClient)
	username := "testuser"
	userDN := "uid=testuser,ou=users"

	expectedSearchEntry := &ldap.Entry{DN: userDN, Attributes: []*ldap.EntryAttribute{{Name: "uid", Values: []string{username}}}}

	gomock.InOrder(
		mockLDAPClient.EXPECT().Connect(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil),
		mockLDAPClient.EXPECT().Bind(idpConfig.LDAP.BindDN, idpConfig.LDAP.BindPassword).Return(nil),
		mockLDAPClient.EXPECT().SearchUser(gomock.Any(), gomock.Any(), gomock.Any()).Return(expectedSearchEntry, nil),
		mockLDAPClient.EXPECT().Bind(userDN, "wrongpassword").Return(ldap.NewError(ldap.LDAPResultInvalidCredentials, errors.New("invalid credentials"))),
		mockLDAPClient.EXPECT().Close(),
	)

	_, err := provider.AuthenticateAndFetchUser(context.Background(), username, "wrongpassword")
	require.Error(t, err)
	assert.True(t, errors.Is(err, federation.ErrInvalidCredentials), "Expected ErrInvalidCredentials")
}

func TestLDAPProvider_AuthenticateAndFetchUser_UserNotFound_AdminSearch(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockLDAPClient := mock_federation.NewMockLDAPClient(ctrl)
	idpConfig := &domain.IdentityProvider{
		Name: "test-ldap", Type: domain.IdPTypeLDAP,
		LDAP: domain.LDAPConfig{
			ServerURL:    "ldap://localhost",
			BindDN:       "cn=admin",
			BindPassword: "adminpass",
			UserBaseDN:   "ou=users",
			UserFilter:   "(uid=%s)",
		},
	}
	provider, _ := federation.NewLDAPProvider(idpConfig, mockLDAPClient)

	gomock.InOrder(
		mockLDAPClient.EXPECT().Connect(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil),
		mockLDAPClient.EXPECT().Bind(idpConfig.LDAP.BindDN, idpConfig.LDAP.BindPassword).Return(nil),
		mockLDAPClient.EXPECT().SearchUser(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, federation.ErrUserNotFound), // Mock SearchUser to return ErrUserNotFound
		mockLDAPClient.EXPECT().Close(),
	)

	_, err := provider.AuthenticateAndFetchUser(context.Background(), "unknownuser", "password")
	require.Error(t, err)
	assert.True(t, errors.Is(err, federation.ErrUserNotFound), "Expected ErrUserNotFound")
}

func TestLDAPProvider_AuthenticateAndFetchUser_UserNotFound_AnonymousSearch(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockLDAPClient := mock_federation.NewMockLDAPClient(ctrl)
	idpConfig := &domain.IdentityProvider{ // No admin bind creds
		Name: "test-ldap", Type: domain.IdPTypeLDAP,
		LDAP: domain.LDAPConfig{
			ServerURL:  "ldap://localhost",
			UserBaseDN: "ou=users",
			UserFilter: "(uid=%s)",
		},
	}
	provider, _ := federation.NewLDAPProvider(idpConfig, mockLDAPClient)
	username := "unknownuser"
	password := "password"

	gomock.InOrder(
		mockLDAPClient.EXPECT().Connect(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil),
		// First bind attempt with username fails (not invalid creds, e.g. needs DN)
		mockLDAPClient.EXPECT().Bind(username, password).Return(ldap.NewError(ldap.LDAPResultInvalidDNSyntax, fmt.Errorf("some other bind error"))),
		// Anonymous bind for search
		mockLDAPClient.EXPECT().Bind("", "").Return(nil),
		// Search fails to find user
		mockLDAPClient.EXPECT().SearchUser(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, federation.ErrUserNotFound),
		mockLDAPClient.EXPECT().Close(),
	)

	_, err := provider.AuthenticateAndFetchUser(context.Background(), username, password)
	require.Error(t, err)
	assert.True(t, errors.Is(err, federation.ErrUserNotFound), "Expected ErrUserNotFound from anonymous search path")
}

func TestLDAPProvider_Misconfigured(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockLDAPClient := mock_federation.NewMockLDAPClient(ctrl)

	// Test case 1: Missing ServerURL
	idpConfig1 := &domain.IdentityProvider{
		Type: domain.IdPTypeLDAP,
		LDAP: domain.LDAPConfig{
			UserBaseDN: "ou=users", UserFilter: "(uid=%s)",
		},
	}
	provider1, _ := federation.NewLDAPProvider(idpConfig1, mockLDAPClient)
	_, err1 := provider1.AuthenticateAndFetchUser(context.Background(), "user", "pass")
	assert.ErrorIs(t, err1, federation.ErrProviderMisconfigured)

	// Test case 2: Missing UserBaseDN
	idpConfig2 := &domain.IdentityProvider{
		Type: domain.IdPTypeLDAP,
		LDAP: domain.LDAPConfig{
			ServerURL: "ldap://host", UserFilter: "(uid=%s)",
		},
	}
	provider2, _ := federation.NewLDAPProvider(idpConfig2, mockLDAPClient)
	_, err2 := provider2.AuthenticateAndFetchUser(context.Background(), "user", "pass")
	assert.ErrorIs(t, err2, federation.ErrProviderMisconfigured)

	// Test case 3: Missing UserFilter
	idpConfig3 := &domain.IdentityProvider{
		Type: domain.IdPTypeLDAP,
		LDAP: domain.LDAPConfig{ServerURL: "ldap://host", UserBaseDN: "ou=users"},
	}
	provider3, _ := federation.NewLDAPProvider(idpConfig3, mockLDAPClient)
	_, err3 := provider3.AuthenticateAndFetchUser(context.Background(), "user", "pass")
	assert.ErrorIs(t, err3, federation.ErrProviderMisconfigured)
}
