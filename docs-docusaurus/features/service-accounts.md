---
id: service-accounts
title: Service Accounts
sidebar_label: Service Accounts
---

# Service Accounts

Service accounts provide machine identities for applications, scripts, and services to authenticate with Shadow SSO.

## Overview

Service accounts are non-human identities that can:

- **Authenticate via JWT** - Sign JWTs with private keys
- **Access APIs** - Call Shadow SSO APIs with proper authorization
- **Act on behalf of users** - Perform delegated operations
- **Automate workflows** - CI/CD pipelines, batch jobs

## Architecture

```
+-------------------+     +-------------------+     +-------------------+
|   Service/App     | --> |   Shadow SSO      | --> |   MongoDB         |
|   (Service        |     |   (JWT Auth)      |     |   (Service        |
|    Account)       |     |                   |     |    Account)       |
+-------------------+     +-------------------+     +-------------------+
        |
        v
+-------------------+
|   JSON Key File   |
|   (Private Key)   |
+-------------------+
```

## Key Format

Service account keys are JSON files similar to Google Cloud service account keys:

```json
{
  "type": "service_account",
  "project_id": "my-project",
  "private_key_id": "key-12345",
  "private_key": "-----BEGIN RSA PRIVATE KEY-----\n...\n-----END RSA PRIVATE KEY-----\n",
  "client_email": "my-sa@my-project.iam.sso.dev",
  "client_id": "sa-client-id",
  "auth_uri": "https://sso.example.com/oauth2/auth",
  "token_uri": "https://sso.example.com/oauth2/token",
  "auth_provider_x509_cert_url": "https://sso.example.com/.well-known/jwks.json",
  "client_x509_cert_url": "https://sso.example.com/.well-known/jwks.json"
}
```

| Field | Description |
|-------|-------------|
| `type` | Always `service_account` |
| `project_id` | Project identifier |
| `private_key_id` | Unique key identifier |
| `private_key` | RSA private key (PEM format) |
| `client_email` | Service account email |
| `client_id` | Associated OAuth client ID |
| `auth_uri` | Authorization endpoint |
| `token_uri` | Token endpoint |
| `auth_provider_x509_cert_url` | JWKS endpoint |

## Creating Service Accounts

### Via CLI

```bash
# Create service account and generate key
ssoctl service-account create-key \
  --project-id my-project \
  --display-name "My Service Account"

# Output: JSON key file content
```

### Via GraphQL

```graphql
mutation {
  createServiceAccount(input: {
    projectId: "my-project"
    displayName: "My Service Account"
    roles: ["api-access"]
  }) {
    id
    key {
      privateKey
      keyId
    }
  }
}
```

## Authentication

### JWT Grant Type

Service accounts authenticate using the `urn:ietf:params:oauth:grant-type:jwt-bearer` grant type:

```bash
# 1. Create JWT assertion
# Header: {"alg": "RS256", "typ": "JWT", "kid": "<private_key_id>"}
# Payload: {
#   "iss": "<client_email>",
#   "sub": "<client_email>",
#   "aud": "https://sso.example.com/oauth2/token",
#   "exp": <now + 1 hour>,
#   "iat": <now>
# }

# 2. Sign JWT with private key

# 3. Exchange JWT for access token
curl -X POST https://sso.example.com/oauth2/token \
  -d "grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer" \
  -d "assertion=<signed-jwt>"
```

### Using ssoctl

```bash
# Authenticate with service account key
ssoctl auth login \
  --service-account-key ./service-account-key.json

# Or set environment variable
export SSSO_SERVICE_ACCOUNT_KEY=./service-account-key.json
ssoctl auth login
```

### Go Client Example

```go
package main

import (
    "context"
    "encoding/json"
    "os"

    "golang.org/x/oauth2"
    "golang.org/x/oauth2/jwt"
)

func main() {
    // Load service account key
    keyFile, _ := os.ReadFile("service-account-key.json")
    var key struct {
        ClientEmail string `json:"client_email"`
        PrivateKey  string `json:"private_key"`
        PrivateKeyID string `json:"private_key_id"`
        TokenURI    string `json:"token_uri"`
    }
    json.Unmarshal(keyFile, &key)

    // Configure JWT config
    config := &jwt.Config{
        Email:        key.ClientEmail,
        PrivateKey:   []byte(key.PrivateKey),
        PrivateKeyID: key.PrivateKeyID,
        TokenURL:     key.TokenURI,
        Scopes:       []string{"api-access"},
    }

    // Get token
    token, _ := config.TokenSource(context.Background()).Token()
    
    // Use token
    client := config.Client(context.Background())
    resp, _ := client.Get("https://sso.example.com/api/resource")
}
```

## Key Management

### List Keys

```bash
# List all keys for a service account
ssoctl service-account list-keys <service-account-id>
```

### Delete Keys

```bash
# Delete a specific key
ssoctl service-account delete-key <service-account-id> <key-id>
```

### Key Rotation

Rotate keys regularly:

```bash
# 1. Create new key
ssoctl service-account create-key \
  --project-id my-project \
  --display-name "My Service Account (New)"

# 2. Update applications to use new key

# 3. Delete old key
ssoctl service-account delete-key <sa-id> <old-key-id>
```

## Authorization

### Assign Roles

```bash
# Assign role to service account
ssoctl service-account update <sa-id> \
  --roles "api-access,admin"
```

### Built-in Roles

| Role | Permissions |
|------|-------------|
| `api-access` | Access protected APIs |
| `user-read` | Read user information |
| `user-write` | Create/update users |
| `client-read` | Read client information |
| `client-write` | Create/update clients |
| `admin` | Full administrative access |

## Security Best Practices

### Key Storage

| Method | Security Level | Use Case |
|--------|---------------|----------|
| Kubernetes Secret | High | K8s deployments |
| HashiCorp Vault | High | Enterprise |
| Environment Variable | Medium | Container apps |
| File on disk | Low | Development only |

### Kubernetes Secret

```bash
# Create secret from key file
kubectl create secret generic my-service-account \
  --from-file=key.json=./service-account-key.json \
  -n my-app

# Mount in pod
# volumes:
#   - name: sa-key
#     secret:
#       secretName: my-service-account
# volumeMounts:
#   - name: sa-key
#     mountPath: /etc/sso
#     readOnly: true
```

### Key Permissions

- Restrict file permissions: `chmod 600 service-account-key.json`
- Never commit keys to version control
- Rotate keys every 90 days
- Use separate service accounts per application

### Audit Logging

All service account authentications are logged:

```json
{
  "level": "info",
  "message": "Service account authenticated",
  "service_account_id": "sa-12345",
  "project_id": "my-project",
  "key_id": "key-67890",
  "scopes": ["api-access"]
}
```

## Troubleshooting

### Invalid JWT

**Error:** `invalid_grant: invalid JWT signature`

**Solutions:**
1. Verify private key matches `private_key_id`
2. Check JWT is not expired
3. Ensure `iss` and `sub` match `client_email`

### Key Not Found

**Error:** `key not found`

**Solutions:**
1. Verify key exists: `ssoctl service-account list-keys <sa-id>`
2. Check `private_key_id` in JWT header
3. Ensure service account is not deleted

### Permission Denied

**Error:** `access denied: insufficient scopes`

**Solutions:**
1. Check service account roles
2. Verify requested scopes are assigned
3. Update roles: `ssoctl service-account update <sa-id> --roles "api-access"`

## Next Steps

- [Federation](/features/federation) - External identity providers
- [LDAP](/features/ldap) - Enterprise directory integration
- [MFA](/features/mfa) - Multi-factor authentication
