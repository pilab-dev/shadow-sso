---
id: federation
title: Identity Provider Federation
sidebar_label: Federation
---

# Identity Provider Federation

Configure external identity providers (IdPs) to allow users to authenticate using accounts from Google, Facebook, Apple, GitHub, or any OIDC-compliant provider.

## Overview

Shadow SSO supports federation with external identity providers using OAuth2/OIDC protocols. This allows:

- **Social login** - Users sign in with Google, Facebook, Apple, GitHub
- **Enterprise SSO** - Connect to corporate identity providers
- **Account linking** - Link external identities to local accounts
- **Seamless onboarding** - Auto-create local accounts on first login

## Supported Providers

| Provider | Protocol | Features |
|----------|----------|----------|
| Google | OIDC | Profile, email |
| Facebook | OAuth2 | Profile, email |
| Apple | OIDC | Profile, email (private relay) |
| GitHub | OAuth2 | Profile, email |
| Custom OIDC | OIDC | Configurable scopes/claims |

## Architecture

```
+-------------------+     +-------------------+     +-------------------+
|   User Browser    | --> |   Shadow SSO      | --> |   External IdP    |
|                   |     |   (Federation     |     |   (Google, etc.)  |
|                   |     |    Service)       |     |                   |
+-------------------+     +-------------------+     +-------------------+
                                  |
                                  v
                          +-------------------+
                          |   MongoDB         |
                          |   (Federated      |
                          |    Identities)    |
                          +-------------------+
```

## Configuration

### Step 1: Register OAuth Application

Register an OAuth application with your identity provider:

#### Google

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project or select existing
3. Navigate to **APIs & Services > Credentials**
4. Create **OAuth 2.0 Client ID**
5. Set authorized redirect URI: `https://sso.example.com/federation/callback`
6. Note the **Client ID** and **Client Secret**

#### GitHub

1. Go to [GitHub Developer Settings](https://github.com/settings/developers)
2. Create **New OAuth App**
3. Set authorization callback URL: `https://sso.example.com/federation/callback`
4. Note the **Client ID** and generate **Client Secret**

#### Apple

1. Go to [Apple Developer](https://developer.apple.com/)
2. Create a **Services ID**
3. Configure **Sign in with Apple**
4. Set return URL: `https://sso.example.com/federation/callback`
5. Download the private key and note the **Key ID**

### Step 2: Configure IdP in Shadow SSO

Use the CLI to add an identity provider:

```bash
# Google
ssoctl idp add \
  --name "google" \
  --type OIDC \
  --oidc-issuer-url https://accounts.google.com \
  --oidc-client-id <your-client-id> \
  --oidc-client-secret <your-client-secret> \
  --oidc-scopes "openid,profile,email"

# GitHub
ssoctl idp add \
  --name "github" \
  --type OIDC \
  --oidc-issuer-url https://github.com \
  --oidc-client-id <your-client-id> \
  --oidc-client-secret <your-client-secret> \
  --oidc-scopes "read:user,user:email"

# Facebook
ssoctl idp add \
  --name "facebook" \
  --type OIDC \
  --oidc-issuer-url https://www.facebook.com \
  --oidc-client-id <your-app-id> \
  --oidc-client-secret <your-app-secret> \
  --oidc-scopes "email,public_profile"
```

### Step 3: Configure Client

Enable federation for specific OAuth clients:

```bash
ssoctl client update <client-id> \
  --federation-enabled \
  --federation-providers google,github
```

## User Flows

### First-Time Login (Auto-Registration)

```
1. User clicks "Sign in with Google"
2. Redirected to Google for authentication
3. Google redirects back with authorization code
4. Shadow SSO exchanges code for tokens
5. Shadow SSO fetches user profile from Google
6. No local account found → auto-create local user
7. Link Google identity to new local user
8. Issue Shadow SSO tokens
```

### Existing User Login

```
1. User clicks "Sign in with Google"
2. Redirected to Google for authentication
3. Google redirects back with authorization code
4. Shadow SSO exchanges code for tokens
5. Shadow SSO fetches user profile from Google
6. Google identity found → link to existing local user
7. Issue Shadow SSO tokens
```

### Account Linking

```
1. User logged in with local credentials
2. User clicks "Link Google Account"
3. Redirected to Google for authentication
4. Google redirects back with authorization code
5. Shadow SSO exchanges code for tokens
6. Link Google identity to current user
7. Future logins can use either method
```

## Account Merging

When a federated login matches an existing local account by email:

1. Shadow SSO detects email match
2. Presents account merge option to user
3. User confirms merge
4. Federated identity linked to existing account
5. All attributes and sessions preserved

## CLI Commands

### Manage Identity Providers

```bash
# List all IdPs
ssoctl idp list

# Get IdP details
ssoctl idp get google

# Update IdP
ssoctl idp update google --enabled false

# Delete IdP
ssoctl idp delete google
```

### Manage User Federated Identities

```bash
# List user's linked identities
ssoctl user federated-identities <user-id>

# Unlink identity
ssoctl user unlink-identity <user-id> --provider google
```

## GraphQL API

### Query Identity Providers

```graphql
query {
  identityProviders {
    id
    name
    type
    enabled
    oidcConfig {
      issuerUrl
      clientId
      scopes
    }
  }
}
```

### Create Identity Provider

```graphql
mutation {
  createIdentityProvider(input: {
    name: "google"
    type: "OIDC"
    enabled: true
    oidcConfig: {
      issuerUrl: "https://accounts.google.com"
      clientId: "your-client-id"
      clientSecret: "your-client-secret"
      scopes: ["openid", "profile", "email"]
    }
  }) {
    id
    name
  }
}
```

## Security Considerations

### Email Verification

By default, federated identities with verified emails are trusted. Configure:

```bash
# Require email verification from IdP
SSSO_FEDERATION_REQUIRE_VERIFIED_EMAIL=true
```

### Account Takeover Prevention

- Email-based auto-linking requires verified emails
- Admin can disable auto-linking: `SSSO_FEDERATION_AUTO_LINK=false`
- Manual linking always requires authentication

### Scope Recommendations

| Provider | Recommended Scopes |
|----------|-------------------|
| Google | `openid`, `profile`, `email` |
| GitHub | `read:user`, `user:email` |
| Facebook | `email`, `public_profile` |
| Apple | `name`, `email` |

## Troubleshooting

### Callback URL Mismatch

**Error:** `redirect_uri_mismatch`

**Solution:** Ensure the callback URL in IdP settings exactly matches:
```
https://sso.example.com/federation/callback
```

### Invalid Client Secret

**Error:** `invalid_client`

**Solution:** Verify client secret is correct and not expired.

### Email Not Returned

**Issue:** User profile doesn't include email.

**Solution:**
- Ensure `email` scope is requested
- For GitHub, ensure user has public email or use `user:email` scope
- For Apple, email may be private relay

### Provider Not Showing

**Issue:** Federation button not appearing in login UI.

**Solution:**
- Check IdP is enabled: `ssoctl idp get <name>`
- Check client has federation enabled
- Check user's client has the provider in allowed list

## Next Steps

- [LDAP Integration](/features/ldap) - Enterprise directory integration
- [Service Accounts](/features/service-accounts) - Machine identities
- [MFA](/features/mfa) - Multi-factor authentication
