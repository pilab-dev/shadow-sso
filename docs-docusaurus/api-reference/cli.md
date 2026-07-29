---
id: cli
title: CLI Reference (ssoctl)
sidebar_label: CLI Reference
---

# ssoctl CLI Reference

`ssoctl` is the command-line interface for managing Shadow SSO.

## Installation

```bash
# Install from source
go install github.com/pilab-dev/shadow-sso/apps/ssoctl@latest

# Or build locally
git clone https://github.com/pilab-dev/shadow-sso.git
cd shadow-sso
go build -o ssoctl ./apps/ssoctl/
```

## Configuration

### Config File Location

```
$HOME/.ssoctl/config.yaml
```

### Context Management

```bash
# Create/set context
ssoctl config set-context my-sso --server https://sso.example.com

# Switch context
ssoctl config use-context my-sso

# List contexts
ssoctl config get-contexts

# Show current context
ssoctl config current-context
```

## Authentication

### Login

```bash
# Interactive login
ssoctl auth login

# Login with credentials
ssoctl auth login --email admin@example.com --password secret
```

### Logout

```bash
ssoctl auth logout
```

### Status

```bash
ssoctl auth status
```

## User Management

### Register User

```bash
ssoctl user register \
  --email user@example.com \
  --password "SecurePass123!" \
  --first-name John \
  --last-name Doe
```

### List Users

```bash
ssoctl user list
ssoctl user list --page-size 50 --page 2
ssoctl user list --status active
```

### Get User

```bash
ssoctl user get user@example.com
ssoctl user get --id user-123
```

### Update User

```bash
ssoctl user update user@example.com \
  --first-name Jane \
  --last-name Smith
```

### Delete User

```bash
ssoctl user delete user@example.com
ssoctl user delete --id user-123 --force
```

### Activate User

```bash
ssoctl user activate user@example.com
```

### Lock User

```bash
ssoctl user lock user@example.com
```

### Unlock User

```bash
ssoctl user unlock user@example.com
```

### Change Password

```bash
ssoctl user change-password user@example.com --new-password "NewPass123!"
```

## Multi-Factor Authentication

### Setup TOTP

```bash
ssoctl user 2fa setup
```

### Verify TOTP

```bash
ssoctl user 2fa verify 123456
```

### Disable 2FA

```bash
ssoctl user 2fa disable -p 123456
```

### Generate Recovery Codes

```bash
ssoctl user 2fa recovery-codes
```

### Check 2FA Status

```bash
ssoctl user 2fa status user@example.com
```

## Client Management

### Register Client

```bash
ssoctl client register \
  --name "My App" \
  --type confidential \
  --redirect-uris https://app.example.com/callback \
  --grant-types authorization_code,refresh_token \
  --scopes openid,profile,email
```

### List Clients

```bash
ssoctl client list
```

### Get Client

```bash
ssoctl client get <client-id>
```

### Update Client

```bash
ssoctl client update <client-id> \
  --name "Updated App" \
  --redirect-uris https://new.example.com/callback
```

### Delete Client

```bash
ssoctl client delete <client-id> --force
```

## Session Management

### List Sessions

```bash
ssoctl session list
ssoctl session list --user user@example.com
```

### Clear Sessions

```bash
# Clear current user's sessions
ssoctl session clear

# Clear specific user's sessions
ssoctl session clear --user user@example.com
```

## Service Account Management

### Create Service Account Key

```bash
ssoctl service-account create-key \
  --project-id my-project \
  --display-name "CI/CD Pipeline"
```

### List Service Account Keys

```bash
ssoctl service-account list-keys <service-account-id>
```

### Delete Service Account Key

```bash
ssoctl service-account delete-key <service-account-id> <key-id>
```

## Identity Provider Management

### Add OIDC Provider

```bash
ssoctl idp add \
  --name google \
  --type OIDC \
  --oidc-issuer-url https://accounts.google.com \
  --oidc-client-id <client-id> \
  --oidc-client-secret <client-secret> \
  --oidc-scopes openid,profile,email
```

### Add LDAP Provider

```bash
ssoctl idp add \
  --name corporate-ldap \
  --type LDAP \
  --ldap-server-url ldaps://ldap.example.com:636 \
  --ldap-user-base-dn "ou=users,dc=example,dc=com" \
  --ldap-user-filter "(uid=%s)" \
  --ldap-bind-dn "cn=sso-service,dc=example,dc=com" \
  --ldap-bind-password "password"
```

### List Identity Providers

```bash
ssoctl idp list
```

### Get Identity Provider

```bash
ssoctl idp get google
```

### Update Identity Provider

```bash
ssoctl idp update google --enabled false
```

### Delete Identity Provider

```bash
ssoctl idp delete google
```

## Global Flags

| Flag | Description |
|------|-------------|
| `--config` | Config file path (default: `$HOME/.ssoctl/config.yaml`) |
| `--context` | Context to use |
| `--output` | Output format: `json`, `yaml`, `table` (default: `table`) |
| `--verbose` | Enable verbose output |
| `--quiet` | Suppress non-essential output |

## Output Formats

### Table (Default)

```bash
ssoctl user list
```

### JSON

```bash
ssoctl user list --output json
```

### YAML

```bash
ssoctl user list --output yaml
```

## Environment Variables

| Variable | Description |
|----------|-------------|
| `SSSOCTL_CONFIG` | Config file path |
| `SSSOCTL_CONTEXT` | Active context |
| `SSSOCTL_SERVER` | Server URL (overrides context) |
| `SSSOCTL_TOKEN` | Auth token (overrides context) |

## Exit Codes

| Code | Description |
|------|-------------|
| `0` | Success |
| `1` | General error |
| `2` | Invalid usage |
| `3` | Authentication failed |
| `4` | Permission denied |
| `5` | Not found |

## Examples

### Complete User Lifecycle

```bash
# Register user
ssoctl user register --email john@example.com --password "Pass123!" --first-name John --last-name Doe

# Activate user
ssoctl user activate john@example.com

# Enable MFA
ssoctl user 2fa setup

# Verify MFA
ssoctl user 2fa verify 123456

# Check status
ssoctl user get john@example.com
```

### Complete Client Setup

```bash
# Register client
ssoctl client register \
  --name "Web App" \
  --type confidential \
  --redirect-uris https://app.example.com/callback \
  --grant-types authorization_code,refresh_token

# Get client details
ssoctl client get <client-id>

# Update redirect URIs
ssoctl client update <client-id> --redirect-uris https://app.example.com/callback,https://staging.example.com/callback
```

### Automation Script

```bash
#!/bin/bash
# Setup new environment

# Login
ssoctl auth login --email admin@example.com --password "$ADMIN_PASSWORD"

# Create users
for user in alice bob charlie; do
  ssoctl user register \
    --email "$user@example.com" \
    --password "TempPass123!" \
    --first-name "$user" \
    --last-name "User"
done

# Create client
ssoctl client register \
  --name "Automation Client" \
  --type confidential \
  --redirect-uris https://app.example.com/callback \
  --grant-types authorization_code,refresh_token

echo "Environment setup complete"
```

## Next Steps

- [gRPC API](/api-reference/grpc) - Programmatic API
- [GraphQL API](/api-reference/graphql) - Administrative API
