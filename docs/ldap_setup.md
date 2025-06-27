# Configuring LDAP / Active Directory Integration

Shadow SSO can be configured to use an external LDAP server (such as OpenLDAP or Microsoft Active Directory) as a user authentication source. This document outlines the steps to configure an LDAP Identity Provider (IdP) and set up client-specific attribute mapping.

## 1. Prerequisites

*   An accessible LDAP or Active Directory server.
*   Shadow SSO server running and `ssoctl` CLI configured.
*   Ensure your Shadow SSO server's protobuf definitions and gRPC handlers have been updated to support LDAP IdP configurations and client LDAP mappings if you are building from a version that includes these CLI changes but not yet the server-side components.

## 2. Configuring an LDAP Identity Provider

You will use `ssoctl idp add` to create a new LDAP IdP configuration.

### Common LDAP Parameters:

When adding an LDAP IdP, you'll need to provide several parameters. Here's an explanation of each:

*   `--name`: A unique name for this IdP configuration (e.g., `mycorp-ldap`, `main-ad`).
*   `--type LDAP`: Specifies that this is an LDAP provider.
*   `--ldap-server-url`: The URL of your LDAP server.
    *   Examples: `ldap://ldap.example.com:389`, `ldaps://ad.example.com:636`
*   `--ldap-user-base-dn`: The base Distinguished Name (DN) under which user entries are located.
    *   Example: `ou=users,dc=example,dc=com`
*   `--ldap-user-filter`: An LDAP filter used to find the user object based on the username they provide at login. The `%s` placeholder will be replaced by the entered username.
    *   OpenLDAP (using `uid`): `(uid=%s)`
    *   Active Directory (using `sAMAccountName`): `(sAMAccountName=%s)`
    *   Active Directory (using `userPrincipalName`): `(userPrincipalName=%s)`
*   `--ldap-bind-dn` (Optional): The DN of an administrative or service account that Shadow SSO can use to bind to LDAP for searching users. This is required if your LDAP server does not allow anonymous searches or if the user's DN needs to be discovered before their own bind attempt.
    *   Example: `cn=readonly-admin,dc=example,dc=com`
*   `--ldap-bind-password` (Optional, Sensitive): The password for the `--ldap-bind-dn` account.
*   `--ldap-attr-username`: The LDAP attribute whose value should be considered the primary username within Shadow SSO (often used for the `preferred_username` claim).
    *   Examples: `uid`, `sAMAccountName`, `cn`
*   `--ldap-attr-email`: The LDAP attribute containing the user's email address.
    *   Example: `mail`
*   `--ldap-attr-firstname`: The LDAP attribute for the user's first name.
    *   Example: `givenName`
*   `--ldap-attr-lastname`: The LDAP attribute for the user's last name.
    *   Example: `sn`
*   `--ldap-attr-groups`: The LDAP attribute that stores the user's group memberships (often multi-valued).
    *   Example: `memberOf` (common in AD), `isMemberOf`
*   `--ldap-starttls`: (true/false) Set to `true` if your LDAP server is on a non-TLS port (e.g., 389) but supports upgrading the connection to TLS via the StartTLS operation. Default is `false`.
*   `--ldap-skip-tls-verify`: (true/false) Set to `true` to skip verification of the LDAP server's TLS certificate. **Warning: This is insecure and should only be used for testing or development with self-signed certificates.** Default is `false`.
*   `--enabled`: (true/false) Whether this IdP configuration is active. Default `true`.
*   `--map-attribute`: (Repeatable) Generic attribute mappings if needed, though client-specific mappings are generally preferred for LDAP user attributes to JWT claims. Format: `'ExternalKey=LocalUserKey'`. For LDAP, these might be less used if client-specific mappings cover JWT claims.

### Example: Adding an OpenLDAP Provider

```bash
ssoctl idp add \
  --name "openldap-main" \
  --type LDAP \
  --ldap-server-url "ldap://ldap.mycompany.com:389" \
  --ldap-user-base-dn "ou=People,dc=mycompany,dc=com" \
  --ldap-user-filter "(uid=%s)" \
  --ldap-bind-dn "cn=sso-service,ou=Services,dc=mycompany,dc=com" \
  --ldap-bind-password "securepassword" \
  --ldap-attr-username "uid" \
  --ldap-attr-email "mail" \
  --ldap-attr-firstname "givenName" \
  --ldap-attr-lastname "sn" \
  --ldap-attr-groups "memberOf" \
  --ldap-starttls true \
  --enabled true
```

### Example: Adding an Active Directory Provider

```bash
ssoctl idp add \
  --name "ad-prod" \
  --type LDAP \
  --ldap-server-url "ldaps://ad.mycorp.local:636" \ # Use ldaps for AD
  --ldap-user-base-dn "OU=Users,OU=Corp,DC=mycorp,DC=local" \
  --ldap-user-filter "(sAMAccountName=%s)" \       # Or (userPrincipalName=%s)
  --ldap-bind-dn "CN=SVC_ShadowSSO,OU=ServiceAccounts,DC=mycorp,DC=local" \
  --ldap-bind-password "complexpassword" \
  --ldap-attr-username "sAMAccountName" \
  --ldap-attr-email "mail" \
  --ldap-attr-firstname "givenName" \
  --ldap-attr-lastname "sn" \
  --ldap-attr-groups "memberOf" \
  --ldap-skip-tls-verify false \ # Set to true only if using self-signed certs for AD LDAPS and understand risks
  --enabled true
```
**Note on Active Directory and `userPrincipalName`:** If you use `(userPrincipalName=%s)` as the filter, users will log in with their UPN (e.g., `user@mycorp.local`). The `sAMAccountName` is typically the shorter, pre-Windows 2000 login name.

### Updating an LDAP IdP

Use `ssoctl idp update [IDP_ID_OR_NAME]` with the same flags as `add` to modify an existing configuration. Only include the flags for parameters you wish to change.

```bash
ssoctl idp update openldap-main --ldap-attr-email "primaryEmail"
```

## 3. Configuring Client-Specific LDAP Attribute Mapping

For each OAuth2 client application that will use this LDAP IdP, you can define how attributes fetched from LDAP are mapped to JWT claims. This provides flexibility if different clients need different claim sets or different LDAP attributes for the same conceptual claim.

These mappings are configured when registering or updating a client using `ssoctl client register` or `ssoctl client update`.

### Client LDAP Mapping Flags:

*   `--ldap-attr-email`: Specifies the LDAP attribute (from the IdP's fetched attributes, available in `ExternalUserInfo.RawData`) to use for the standard `email` and `email_verified` JWT claims for this client. If not set, the default `email` from the IdP configuration (via `LDAPAttributeEmail`) or `ExternalUserInfo.Email` might be used.
*   `--ldap-attr-firstname`: LDAP attribute for the `given_name` JWT claim for this client.
*   `--ldap-attr-lastname`: LDAP attribute for the `family_name` JWT claim for this client.
*   `--ldap-attr-groups`: LDAP attribute for the `groups` (or `roles`) JWT claim for this client. The values from this LDAP attribute (often multi-valued) will be included in the claim.
*   `--ldap-custom-claims`: A repeatable flag to map arbitrary LDAP attributes to specific JWT claim names for this client.
    *   Format: `jwt_claim_name=ldap_attribute_name`
    *   Example: `--ldap-custom-claims "employee_id=employeeNumber" --ldap-custom-claims "department=departmentName"`

### Example: Registering a Client with LDAP Mappings

```bash
ssoctl client register \
  --name "My LDAP-Authenticated App" \
  --type confidential \
  --redirect-uris "https://myapp.example.com/callback" \
  --scopes "openid profile email groups employee_info" \
  --grant-types "authorization_code,refresh_token" \
  --ldap-attr-email "mail" \                       # Use 'mail' LDAP attribute for email claim
  --ldap-attr-firstname "givenName" \
  --ldap-attr-lastname "sn" \
  --ldap-attr-groups "memberOf" \                   # Use 'memberOf' for groups claim
  --ldap-custom-claims "employee_id=employeeNumber" \ # Custom claim
  --ldap-custom-claims "user_guid=objectGUID"       # Another custom claim (ensure objectGUID is fetched by IdP config or general fetch)
```

### Example: Updating a Client with LDAP Mappings

```bash
ssoctl client update my-client-id \
  --ldap-attr-email "userPrincipalName" \ # Change email source for this client
  --ldap-custom-claims "office_location=physicalDeliveryOfficeName" # Add/update custom claim
```
To clear a specific client LDAP attribute mapping (e.g., stop overriding the IdP default for email), you might need to set the flag to an empty string if the CLI and server support it, or remove it via an API if direct "unset" isn't supported by flags. For custom claims, providing an empty map or a specific "clear" command might be needed (current CLI likely replaces the whole map).

## 4. Authentication Flow

1.  The user attempts to log in to an application (OAuth2 client).
2.  The application redirects the user to Shadow SSO's authorization endpoint.
3.  If the client is configured to use a specific LDAP IdP (or the user chooses it), Shadow SSO will present a login form for username and password.
    *   Alternatively, for a fully integrated experience, the `/auth/ldap/{providerName}/login` endpoint can be called directly by a custom login page.
4.  The user enters their LDAP credentials.
5.  Shadow SSO's `LDAPLoginHandler` calls the `federation.Service`'s `AuthenticateDirect` method.
6.  The `LDAPProvider` connects to the configured LDAP server.
    *   It may first bind using the admin/service account (`LDAPBindDN`) to search for the user's DN based on `LDAPUserFilter`.
    *   It then attempts to bind as the discovered user DN with the provided password to verify credentials.
    *   Alternatively, if no admin bind DN is set, it might try a direct bind with the provided username or an anonymous search.
7.  If authentication is successful, LDAP attributes are fetched.
8.  The `LDAPLoginHandler` retrieves the OAuth2 client's specific LDAP attribute mapping configuration.
9.  It maps the fetched LDAP attributes to JWT claims according to these client-specific rules (and any IdP-level defaults if applicable).
10. Shadow SSO issues JWTs (ID token, access token) containing these mapped claims back to the client application.

## Troubleshooting

*   **Connection Issues:** Verify LDAP server URL, port, and firewall rules. Use `ldapsearch` or a similar tool from the Shadow SSO server to test connectivity. Check if StartTLS is required or if LDAPS is used.
*   **Authentication Failures:**
    *   Double-check `LDAPBindDN` and `LDAPBindPassword` if used. Ensure the account has permissions to search.
    *   Verify `LDAPUserBaseDN` and `LDAPUserFilter`. Test the filter with `ldapsearch`.
    *   Ensure the attributes specified in `LDAPAttribute...` flags exist for users.
    *   Check Shadow SSO server logs for detailed error messages from the LDAP provider.
*   **Attribute Mapping Issues:**
    *   Ensure the LDAP attribute names in the client configuration (`--ldap-attr-*`, `--ldap-custom-claims`) exactly match the attribute names returned by your LDAP server. LDAP attribute names are case-sensitive in some contexts or for some libraries.
    *   Verify that the `ExternalUserInfo.RawData` (logged by the handler during debugging) contains the expected attributes from LDAP.
*   **TLS/SSL:** If using `ldaps://` or `--ldap-starttls true`, ensure the LDAP server's certificate is trusted by the Shadow SSO server. If using self-signed certificates for testing, `--ldap-skip-tls-verify true` can be used, but **never in production**.

By following these steps, you can integrate your LDAP or Active Directory server as a robust authentication source for applications protected by Shadow SSO.
