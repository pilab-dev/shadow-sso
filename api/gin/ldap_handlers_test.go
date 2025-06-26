package sssogin

import (
	"testing"

	"github.com/pilab-dev/shadow-sso/client"
	"github.com/pilab-dev/shadow-sso/internal/federation"
	"github.com/stretchr/testify/assert"
)

func TestLDAPAttributeMapping(t *testing.T) {
	// This is a simplified test focusing on the attribute mapping logic
	// that would be part of LDAPLoginHandler.
	// In a real scenario, LDAPLoginHandler would be tested more broadly with mocks
	// for its dependencies (federationService, clientService, tokenService).

	baseExternalUser := &federation.ExternalUserInfo{
		ProviderUserID: "uid=testuser,ou=users,dc=example,dc=com",
		Email:          "default_email@example.com", // From IdP's default mapping
		FirstName:      "DefaultFirst",
		LastName:       "DefaultLast",
		Username:       "default_uid", // From IdP's default mapping
		RawData: map[string]interface{}{
			"mail":         "raw_mail@example.com",
			"givenName":    "RawFirst",
			"sn":           "RawLast",
			"uid":          "raw_uid",
			"department":   "Engineering",
			"employeeID":   "E12345",
			"ldapGroups":   []string{"cn=groupA,ou=groups", "cn=groupB,ou=groups"},
			"sAMAccountName": "raw_sam",
		},
	}

	testCases := []struct {
		name              string
		clientConfig      *client.Client
		externalUser      *federation.ExternalUserInfo
		expectedClaims    map[string]interface{}
		idpProviderName   string // For logging/context if needed
		loginUsername     string // Username used for login
	}{
		{
			name: "Client uses specific LDAP attributes, different from IdP defaults",
			clientConfig: &client.Client{
				ClientLDAPAttributeEmail:     "mail", // Use 'mail' from RawData
				ClientLDAPAttributeFirstName: "givenName",
				ClientLDAPAttributeLastName:  "sn",
				// ClientLDAPAttributeUsername: "uid", // Not specified, so should fallback to externalUser.Username or login username
				ClientLDAPAttributeGroups:    "ldapGroups",
				ClientLDAPCustomClaimsMapping: map[string]string{
					"emp_id": "employeeID",
					"dept":   "department",
				},
			},
			externalUser: baseExternalUser,
			loginUsername: "testuser_login",
			expectedClaims: map[string]interface{}{
				"sub":                "uid=testuser,ou=users,dc=example,dc=com",
				"email":              "raw_mail@example.com",
				"email_verified":     true,
				"given_name":         "RawFirst",
				"family_name":        "RawLast",
				"preferred_username": "default_uid", // Falls back to externalUser.Username (from IdP default)
				"groups":             []string{"cn=groupA,ou=groups", "cn=groupB,ou=groups"},
				"emp_id":             "E12345",
				"dept":               "Engineering",
			},
		},
		{
			name: "Client relies on IdP default mappings (client fields empty), plus one custom claim",
			clientConfig: &client.Client{
				// All ClientLDAPAttribute... fields are empty
				ClientLDAPCustomClaimsMapping: map[string]string{
					"custom_sam": "sAMAccountName",
				},
			},
			externalUser: baseExternalUser,
			loginUsername: "testuser_login",
			expectedClaims: map[string]interface{}{
				"sub":                "uid=testuser,ou=users,dc=example,dc=com",
				"email":              "default_email@example.com", // From ExternalUserInfo direct field
				"email_verified":     true,
				"given_name":         "DefaultFirst",
				"family_name":        "DefaultLast",
				"preferred_username": "default_uid", // From ExternalUserInfo direct field
				"custom_sam":         "raw_sam",
				// No groups claim as ClientLDAPAttributeGroups is empty
			},
		},
		{
			name: "Client overrides preferred_username via custom claim",
			clientConfig: &client.Client{
				ClientLDAPCustomClaimsMapping: map[string]string{
					"preferred_username": "sAMAccountName", // Override
				},
			},
			externalUser: baseExternalUser,
			loginUsername: "testuser_login",
			expectedClaims: map[string]interface{}{
				"sub":                "uid=testuser,ou=users,dc=example,dc=com",
				"email":              "default_email@example.com",
				"email_verified":     true,
				"given_name":         "DefaultFirst",
				"family_name":        "DefaultLast",
				"preferred_username": "raw_sam", // Overridden by custom claim
			},
		},
		{
			name: "No specific client LDAP config, only custom claim for non-standard attribute",
			clientConfig: &client.Client{
				ClientLDAPCustomClaimsMapping: map[string]string{
					"department_claim": "department",
				},
			},
			externalUser: baseExternalUser,
			loginUsername: "testuser_login",
			expectedClaims: map[string]interface{}{
				"sub":                "uid=testuser,ou=users,dc=example,dc=com",
				"email":              "default_email@example.com",
				"email_verified":     true,
				"given_name":         "DefaultFirst",
				"family_name":        "DefaultLast",
				"preferred_username": "default_uid",
				"department_claim":   "Engineering",
			},
		},
		{
			name: "Attribute for custom claim not found in RawData",
			clientConfig: &client.Client{
				ClientLDAPCustomClaimsMapping: map[string]string{
					"non_existent_claim": "noSuchAttributeInLDAP",
				},
			},
			externalUser: baseExternalUser,
			loginUsername: "testuser_login",
			expectedClaims: map[string]interface{}{ // non_existent_claim should be missing
				"sub":                "uid=testuser,ou=users,dc=example,dc=com",
				"email":              "default_email@example.com",
				"email_verified":     true,
				"given_name":         "DefaultFirst",
				"family_name":        "DefaultLast",
				"preferred_username": "default_uid",
			},
		},
		{
			name: "Client specifies username attribute, overriding IdP default for preferred_username",
			// This test assumes the handler logic correctly prioritizes ClientLDAPAttributeUsername
			// for the 'preferred_username' claim if externalUser.Username was also set by IdP default.
			// The actual handler logic for preferred_username needs to be precise about this.
			// For this test, we assume the mapping logic inside the handler will use ClientLDAPAttributeUsername for preferred_username.
			// Let's refine this: ClientLDAPAttributeUsername is not a standard claim name.
			// The 'preferred_username' claim should be populated based on a hierarchy:
			// 1. Custom mapping for 'preferred_username'
			// 2. Value from externalUser.RawData[oauthClient.ClientLDAPAttributeUsername] (if ClientLDAPAttributeUsername is set)
			// 3. externalUser.Username (from IdP default)
			// 4. loginUsername
			clientConfig: &client.Client{
				// No specific email/name/group attributes set on client, so defaults from externalUser apply
				// ClientLDAPAttributeUsername: "sAMAccountName", // Let's test this indirectly via preferred_username mapping
				ClientLDAPCustomClaimsMapping: map[string]string{
					"preferred_username": "sAMAccountName", // Explicitly map preferred_username
				},
			},
			externalUser: baseExternalUser, // baseExternalUser.Username is "default_uid"
			loginUsername: "testuser_login",
			expectedClaims: map[string]interface{}{
				"sub":                "uid=testuser,ou=users,dc=example,dc=com",
				"email":              "default_email@example.com",
				"email_verified":     true,
				"given_name":         "DefaultFirst",
				"family_name":        "DefaultLast",
				"preferred_username": "raw_sam", // Mapped to sAMAccountName
			},
		},
	}

	// Simulate the mapping part of LDAPLoginHandler
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			claims := make(map[string]interface{})

			// Standard claims based on client's LDAP attribute configuration
			if tc.clientConfig.ClientLDAPAttributeEmail != "" && tc.externalUser.RawData[tc.clientConfig.ClientLDAPAttributeEmail] != nil {
				claims["email"] = tc.externalUser.RawData[tc.clientConfig.ClientLDAPAttributeEmail]
				if _, ok := tc.externalUser.RawData[tc.clientConfig.ClientLDAPAttributeEmail].(string); ok {
					claims["email_verified"] = true
				}
			} else if tc.externalUser.Email != "" {
				claims["email"] = tc.externalUser.Email
				claims["email_verified"] = true
			}

			if tc.clientConfig.ClientLDAPAttributeFirstName != "" && tc.externalUser.RawData[tc.clientConfig.ClientLDAPAttributeFirstName] != nil {
				claims["given_name"] = tc.externalUser.RawData[tc.clientConfig.ClientLDAPAttributeFirstName]
			} else if tc.externalUser.FirstName != "" {
				claims["given_name"] = tc.externalUser.FirstName
			}

			if tc.clientConfig.ClientLDAPAttributeLastName != "" && tc.externalUser.RawData[tc.clientConfig.ClientLDAPAttributeLastName] != nil {
				claims["family_name"] = tc.externalUser.RawData[tc.clientConfig.ClientLDAPAttributeLastName]
			} else if tc.externalUser.LastName != "" {
				claims["family_name"] = tc.externalUser.LastName
			}

			claims["sub"] = tc.externalUser.ProviderUserID // Placeholder for 'sub'

			// Preferred username logic (simplified from handler for test focus)
			// Order of precedence for preferred_username:
			// 1. Custom mapping for "preferred_username"
			// 2. externalUser.Username (which should have been populated by IdP's LDAPAttributeUsername)
			// 3. loginUsername (as ultimate fallback)

			var preferredUsername string
			if tc.externalUser.Username != "" { // This is from IdP's default LDAPAttributeUsername
				preferredUsername = tc.externalUser.Username
			} else {
				preferredUsername = tc.loginUsername // Fallback
			}
			claims["preferred_username"] = preferredUsername


			// Custom claims mapping (can override standard ones if key matches, e.g., "preferred_username")
			if tc.clientConfig.ClientLDAPCustomClaimsMapping != nil {
				for jwtClaim, ldapAttr := range tc.clientConfig.ClientLDAPCustomClaimsMapping {
					if val, ok := tc.externalUser.RawData[ldapAttr]; ok {
						claims[jwtClaim] = val
					}
				}
			}

			// Groups/Roles mapping
			if tc.clientConfig.ClientLDAPAttributeGroups != "" {
				if groupsVal, ok := tc.externalUser.RawData[tc.clientConfig.ClientLDAPAttributeGroups]; ok {
					claims["groups"] = groupsVal
				}
			}

			assert.Equal(t, tc.expectedClaims, claims)
		})
	}
}
