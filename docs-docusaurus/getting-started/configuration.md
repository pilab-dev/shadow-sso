---
id: configuration
title: Configuration Basics
sidebar_label: Configuration Basics
---

# Configuration Basics

Shadow SSO uses a flexible configuration system supporting environment variables, configuration files, and command-line flags.

## Configuration Sources (Priority Order)

1. **Environment variables** (highest priority)
2. **Configuration file** (`sso_config.yaml`)
3. **Default values** (lowest priority)

## Configuration File Locations

Shadow SSO searches for configuration files in these locations (in order):

1. `./sso_config.yaml` (current directory)
2. `/etc/sso/sso_config.yaml`
3. `$HOME/.sso/sso_config.yaml`

## Environment Variables

All configuration options can be set via environment variables with the `SSSO_` prefix:

```bash
export SSSO_HTTP_ADDR=0.0.0.0:8080
export SSSO_MONGO_URI=mongodb://localhost:27017
export SSSO_ISSUER_URL=https://sso.example.com
```

## Essential Configuration

### Core Settings

| Variable | Default | Description |
|----------|---------|-------------|
| `SSSO_HTTP_ADDR` | `0.0.0.0:8080` | HTTP server address |
| `SSSO_MGMT_HTTP_ADDR` | `:5000` | Management server address (health, metrics) |
| `SSSO_ISSUER_URL` | `http://localhost:8080` | OIDC issuer URL |
| `SSSO_LOG_LEVEL` | `info` | Log level: `debug`, `info`, `warn`, `error` |

### Database Settings

| Variable | Default | Description |
|----------|---------|-------------|
| `SSSO_MONGO_URI` | `mongodb://localhost:27017` | MongoDB connection URI |
| `SSSO_MONGO_DB_NAME` | `shadow_sso_db` | MongoDB database name |
| `SSSO_STORAGE_BACKEND` | `mongodb` | Storage backend: `mongodb` or `dts` |

### Security Settings

| Variable | Default | Description |
|----------|---------|-------------|
| `SSSO_SIGNING_KEY_PATH` | (required) | Path to RSA private key for JWT signing |
| `SSSO_CONFIG_ENCRYPTION_KEY` | (auto-generated) | 32-byte key for encrypting sensitive config |
| `SSSO_KEY_ROTATION_INTERVAL` | `24h` | JWKS key rotation interval |

### Initial Admin Setup

| Variable | Default | Description |
|----------|---------|-------------|
| `SSSO_INITIAL_ADMIN_ENABLED` | `false` | Enable automatic admin creation |
| `SSSO_INITIAL_ADMIN_EMAIL` | - | Admin email address |
| `SSSO_INITIAL_ADMIN_PASSWORD` | - | Admin password |

## Example Configuration File

```yaml
# sso_config.yaml

# Server Configuration
http_addr: "0.0.0.0:8080"
mgmt_http_addr: ":5000"
log_level: "info"
json_log: true

# OIDC Configuration
issuer_url: "https://sso.example.com"
key_rotation_interval: "24h"

# Database Configuration
mongo_uri: "mongodb://user:pass@mongo:27017/shadow_sso?authSource=admin"
mongo_db_name: "shadow_sso"
storage_backend: "mongodb"

# Security Configuration
signing_key_path: "/etc/sso/keys/private.pem"
config_encryption_key: "your-32-byte-encryption-key-here"

# Initial Admin
initial_admin_enabled: true
initial_admin_email: "admin@example.com"
initial_admin_password: "change-me-immediately"

# External Login UI (optional)
nextjs_login_url: "https://login.example.com"

# CORS Configuration
allowed_origins:
  - "https://app.example.com"
  - "https://admin.example.com"
```

## Configuration Validation

Shadow SSO validates configuration on startup. Common errors:

| Error | Cause | Solution |
|-------|-------|----------|
| `signing_key_path is required` | No signing key configured | Set `SSSO_SIGNING_KEY_PATH` or generate a key |
| `config_encryption_key is required` | Encryption key missing | Set `SSSO_CONFIG_ENCRYPTION_KEY` |
| `mongo connection failed` | MongoDB unreachable | Check `SSSO_MONGO_URI` and network |

## Next Steps

- [Full Configuration Reference](/configuration/reference) - All available options
- [Deployment Guide](/deployment/docker) - Deploy with your configuration
- [Security Best Practices](/operations/security) - Secure your deployment
