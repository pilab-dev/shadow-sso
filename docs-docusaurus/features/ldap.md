---
id: ldap
title: LDAP / Active Directory
sidebar_label: LDAP
---

# LDAP / Active Directory Integration

Integrate Shadow SSO with LDAP or Active Directory for enterprise user authentication.

## Overview

Shadow SSO can authenticate users against an external LDAP or Active Directory server. This enables:

- **Enterprise SSO** - Use existing corporate credentials
- **Centralized authentication** - Single source of truth for users
- **Group-based access** - Leverage LDAP groups for authorization
- **Attribute mapping** - Sync user attributes from LDAP

## Architecture

```
+-------------------+     +-------------------+     +-------------------+
|   User Browser    | --> |   Shadow SSO      | --> |   LDAP/AD         |
|                   |     |   (LDAP Auth)     |     |   Server          |
+-------------------+     +-------------------+     +-------------------+
                                  |
                                  v
                          +-------------------+
                          |   MongoDB         |
                          |   (Local User     |
                          |    Record)        |
                          +-------------------+
```

## Prerequisites

- LDAP or Active Directory server accessible from Shadow SSO
- LDAP bind credentials (service account)
- Knowledge of LDAP schema (user DN, group DN, attributes)

## Configuration

### Step 1: Add LDAP Identity Provider

```bash
ssoctl idp add \
  --name "corporate-ldap" \
  --type LDAP \
  --ldap-server-url "ldaps://ldap.example.com:636" \
  --ldap-user-base-dn "ou=users,dc=example,dc=com" \
  --ldap-user-filter "(uid=%s)" \
  --ldap-bind-dn "cn=sso-service,dc=example,dc=com" \
  --ldap-bind-password "service-account-password" \
  --ldap-attribute-mapping "email=mail,firstName=givenName,lastName=sn"
```

### Step 2: Configure for Active Directory

For Active Directory, use these settings:

```bash
ssoctl idp add \
  --name "corporate-ad" \
  --type LDAP \
  --ldap-server-url "ldaps://ad.example.com:636" \
  --ldap-user-base-dn "dc=example,dc=com" \
  --ldap-user-filter "(sAMAccountName=%s)" \
  --ldap-bind-dn "CN=sso-service,OU=Service Accounts,DC=example,DC=com" \
  --ldap-bind-password "service-account-password" \
  --ldap-attribute-mapping "email=userPrincipalName,firstName=givenName,lastName=sn,displayName=displayName"
```

### Step 3: Enable LDAP for Clients

```bash
ssoctl client update <client-id> \
  --ldap-enabled \
  --ldap-idp "corporate-ldap"
```

## LDAP Parameters

| Parameter | Description | Example |
|-----------|-------------|---------|
| `--ldap-server-url` | LDAP server URL | `ldaps://ldap.example.com:636` |
| `--ldap-user-base-dn` | Base DN for user search | `ou=users,dc=example,dc=com` |
| `--ldap-user-filter` | Filter to find user by username | `(uid=%s)` or `(sAMAccountName=%s)` |
| `--ldap-bind-dn` | Service account DN for search | `cn=sso-service,dc=example,dc=com` |
| `--ldap-bind-password` | Service account password | `password` |
| `--ldap-attribute-mapping` | Map LDAP attrs to user fields | `email=mail,firstName=givenName` |
| `--ldap-group-base-dn` | Base DN for group search | `ou=groups,dc=example,dc=com` |
| `--ldap-group-filter` | Filter for group membership | `(member=%s)` |

## User Filter Examples

### OpenLDAP

```bash
# By uid
--ldap-user-filter "(uid=%s)"

# By mail
--ldap-user-filter "(mail=%s)"

# By employeeNumber
--ldap-user-filter "(employeeNumber=%s)"
```

### Active Directory

```bash
# By sAMAccountName (Windows username)
--ldap-user-filter "(sAMAccountName=%s)"

# By userPrincipalName (email-like)
--ldap-user-filter "(userPrincipalName=%s)"

# By mail
--ldap-user-filter "(mail=%s)"
```

## Attribute Mapping

Map LDAP attributes to Shadow SSO user fields:

```bash
--ldap-attribute-mapping "email=mail,firstName=givenName,lastName=sn,displayName=displayName,phone=telephoneNumber"
```

| Shadow SSO Field | Common LDAP Attributes |
|-----------------|----------------------|
| `email` | `mail`, `userPrincipalName`, `email` |
| `firstName` | `givenName`, `firstName` |
| `lastName` | `sn`, `surname`, `lastName` |
| `displayName` | `displayName`, `cn` |
| `phone` | `telephoneNumber`, `mobile` |

## Authentication Flow

### LDAP Authentication

```
1. User enters username and password
2. Shadow SSO binds with service account
3. Shadow SSO searches for user by filter
4. Shadow SSO attempts user bind with provided password
5. If bind succeeds → authentication successful
6. Shadow SSO fetches user attributes
7. Create/update local user record
8. Issue Shadow SSO tokens
```

### User Provisioning

On first LDAP login:

1. Local user record created in MongoDB
2. LDAP attributes mapped to user fields
3. User marked as "federated" (LDAP source)
4. Subsequent logins update local record

## Group Mapping

### Map LDAP Groups to Roles

```bash
ssoctl client update <client-id> \
  --ldap-group-base-dn "ou=groups,dc=example,dc=com" \
  --ldap-group-filter "(member=%s)" \
  --ldap-group-role-mapping "admin=CN=SSO Admins,OU=Groups,DC=example,DC=com"
```

### Group Filter Examples

```bash
# Active Directory (member attribute)
--ldap-group-filter "(member=%s)"

# OpenLDAP (memberUid attribute)
--ldap-group-filter "(memberUid=%s)"

# Nested groups (Active Directory)
--ldap-group-filter "(member:1.2.840.113556.1.4.1941:=%s)"
```

## TLS Configuration

### LDAPS (Recommended)

```bash
ssoctl idp add \
  --name "secure-ldap" \
  --type LDAP \
  --ldap-server-url "ldaps://ldap.example.com:636" \
  # ... other parameters
```

### StartTLS

```bash
ssoctl idp add \
  --name "starttls-ldap" \
  --type LDAP \
  --ldap-server-url "ldap://ldap.example.com:389" \
  --ldap-starttls true \
  # ... other parameters
```

### Custom CA Certificate

```bash
# Mount CA certificate
-v /path/to/ca.pem:/etc/sso/ldap/ca.pem:ro

# Configure in IdP
--ldap-tls-ca-cert "/etc/sso/ldap/ca.pem"
```

## GraphQL API

### Query LDAP IdP

```graphql
query {
  identityProvider(id: "corporate-ldap") {
    name
    type
    ldapConfig {
      serverUrl
      userBaseDn
      userFilter
      bindDn
      attributeMapping
    }
  }
}
```

### Update LDAP IdP

```graphql
mutation {
  updateIdentityProvider(id: "corporate-ldap", input: {
    ldapConfig: {
      userFilter: "(mail=%s)"
      attributeMapping: {
        email: "mail"
        firstName: "givenName"
      }
    }
  }) {
    id
    name
  }
}
```

## Troubleshooting

### Connection Failed

**Error:** `failed to connect to LDAP server`

**Diagnosis:**

```bash
# Test LDAP connectivity
openssl s_client -connect ldap.example.com:636

# Check DNS
nslookup ldap.example.com

# Check firewall
nc -zv ldap.example.com 636
```

### Bind Failed

**Error:** `LDAP bind failed: invalid credentials`

**Solutions:**
1. Verify bind DN and password
2. Check service account has search permissions
3. Ensure DN format is correct (escape special characters)

### User Not Found

**Error:** `user not found in LDAP`

**Diagnosis:**

```bash
# Test search manually
ldapsearch -H ldaps://ldap.example.com \
  -D "cn=sso-service,dc=example,dc=com" \
  -W \
  -b "ou=users,dc=example,dc=com" \
  "(uid=testuser)"
```

**Common Issues:**
- Wrong base DN
- Wrong user filter
- User doesn't exist in LDAP
- Service account lacks search permissions

### Attribute Not Mapped

**Issue:** User created but fields are empty.

**Solutions:**
1. Check attribute names in LDAP:
   ```bash
   ldapsearch -H ldaps://ldap.example.com -b "ou=users,dc=example,dc=com" "(uid=testuser)"
   ```
2. Verify attribute mapping syntax: `email=mail,firstName=givenName`
3. Ensure LDAP attributes exist for the user

### Group Membership Not Working

**Issue:** User not getting expected roles from groups.

**Diagnosis:**

```bash
# Check group membership
ldapsearch -H ldaps://ldap.example.com \
  -b "ou=groups,dc=example,dc=com" \
  "(member=cn=testuser,ou=users,dc=example,dc=com)"
```

**Common Issues:**
- Wrong group base DN
- Wrong group filter
- Group attribute mismatch (`member` vs `memberUid`)
- Nested groups not resolved

## Security Considerations

### Service Account Security

- Use dedicated service account with minimal permissions
- Restrict to read-only access
- Rotate password regularly
- Store password in Kubernetes secret or vault

### TLS Requirements

- Always use LDAPS (port 636) or StartTLS
- Verify server certificate
- Use strong cipher suites

### Audit Logging

LDAP authentications are logged:

```json
{
  "level": "info",
  "message": "LDAP authentication successful",
  "user": "testuser",
  "idp": "corporate-ldap",
  "ldap_dn": "cn=testuser,ou=users,dc=example,dc=com"
}
```

## Next Steps

- [Federation](/features/federation) - OAuth/OIDC federation
- [Service Accounts](/features/service-accounts) - Machine identities
- [MFA](/features/mfa) - Multi-factor authentication
