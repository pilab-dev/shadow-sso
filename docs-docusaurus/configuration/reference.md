---
id: reference
title: Configuration Reference
sidebar_label: Configuration Reference
---

# Configuration Reference

Complete reference for all Shadow SSO configuration options.

## Configuration Methods

Shadow SSO supports three configuration methods (in priority order):

1. **Environment variables** (prefix: `SSSO_`)
2. **Configuration file** (`sso_config.yaml`)
3. **Default values**

## Core Server Configuration

| Environment Variable | Config Key | Default | Description |
|---------------------|------------|---------|-------------|
| `SSSO_HTTP_ADDR` | `http_addr` | `0.0.0.0:8080` | HTTP server listen address |
| `SSSO_MGMT_HTTP_ADDR` | `mgmt_http_addr` | `:5000` | Management server address (health, metrics) |
| `SSSO_LOG_LEVEL` | `log_level` | `info` | Log level: `debug`, `info`, `warn`, `error` |
| `SSSO_JSON_LOG` | `json_log` | `false` | Enable JSON structured logging |
| `SSSO_ISSUER_URL` | `issuer_url` | `http://localhost:8080` | OIDC issuer URL (used in tokens) |
| `SSSO_DEFAULT_REDIRECT_URI` | `default_redirect_uri` | `http://localhost:3000/login` | Default OAuth2 redirect URI |

## Database Configuration

| Environment Variable | Config Key | Default | Description |
|---------------------|------------|---------|-------------|
| `SSSO_MONGO_URI` | `mongo_uri` | `mongodb://localhost:27017` | MongoDB connection URI |
| `SSSO_MONGO_DB_NAME` | `mongo_db_name` | `shadow_sso_db` | MongoDB database name |
| `SSSO_STORAGE_BACKEND` | `storage_backend` | `mongodb` | Storage backend: `mongodb` or `dts` |

### MongoDB URI Format

```
mongodb://[username:password@]host1[:port1][,...hostN[:portN]][/[database][?options]]
```

**Examples:**

```bash
# Simple local
SSSO_MONGO_URI=mongodb://localhost:27017

# With authentication
SSSO_MONGO_URI=mongodb://user:pass@mongo:27017/shadow_sso?authSource=admin

# Replica set
SSSO_MONGO_URI=mongodb://user:pass@mongo1:27017,mongo2:27017,mongo3:27017/shadow_sso?replicaSet=rs0

# TLS enabled
SSSO_MONGO_URI=mongodb://user:pass@mongo:27017/shadow_sso?tls=true&tlsCAFile=/path/to/ca.pem
```

## Distributed Token Store (DTS) Configuration

| Environment Variable | Config Key | Default | Description |
|---------------------|------------|---------|-------------|
| `SSSO_DTS_CLIENT_ADDRESS` | `dts_client_address` | `localhost:50051` | DTS gRPC server address |
| `SSSO_DTS_TIMEOUT` | `dts_connect_timeout` | `5s` | DTS connection timeout |

### DTS Service Configuration

The DTS service (`ssso-dts`) has its own configuration:

| Environment Variable | Default | Description |
|---------------------|---------|-------------|
| `DTS_GRPC_SERVER_ADDRESS` | `0.0.0.0:50051` | gRPC listen address |
| `DTS_BBOLTDB_PATH` | `/data/dts.db` | BBoltDB database file path |
| `DTS_DEFAULT_TTL_SECONDS` | `3600` | Default TTL for stored items |
| `DTS_CLEANUP_INTERVAL_SECONDS` | `600` | Expired item cleanup interval |
| `DTS_MAX_MSG_SIZE_BYTES` | `16777216` | Max gRPC message size (16MB) |

## Security Configuration

| Environment Variable | Config Key | Default | Description |
|---------------------|------------|---------|-------------|
| `SSSO_SIGNING_KEY_PATH` | `signing_key_path` | *(required)* | Path to RSA private key PEM file |
| `SSSO_CONFIG_ENCRYPTION_KEY` | `config_encryption_key` | *(auto-generated)* | 32-byte hex key for encrypting sensitive data |
| `SSSO_KEY_ROTATION_INTERVAL` | `key_rotation_interval` | `24h` | JWKS key rotation interval |
| `SSSO_TOKEN_SIGNING_KEY` | `token_signing_key` | - | Inline token signing key (alternative to file) |
| `SSSO_TOKEN_SIGNING_KEY_FILE` | `token_signing_key_file` | - | Alternative signing key file path |
| `SSSO_BOOTSTRAP_TOKEN` | `bootstrap_token` | - | Bootstrap token for admin client access |

### Generating a Signing Key

```bash
openssl genrsa -out private.pem 2048
```

### Generating an Encryption Key

```bash
openssl rand -hex 32
```

## Token Configuration

| Environment Variable | Config Key | Default | Description |
|---------------------|------------|---------|-------------|
| `SSSO_ACCESS_TOKEN_TTL` | `access_token_ttl` | `1h` | Access token lifetime |
| `SSSO_REFRESH_TOKEN_TTL` | `refresh_token_ttl` | `720h` | Refresh token lifetime (30 days) |
| `SSSO_TOKEN_CACHE_DEFAULT_TTL` | `token_cache_default_ttl` | `1h` | Token cache TTL |

## Initial Admin Configuration

| Environment Variable | Config Key | Default | Description |
|---------------------|------------|---------|-------------|
| `SSSO_INITIAL_ADMIN_ENABLED` | `initial_admin_enabled` | `false` | Enable automatic admin user creation |
| `SSSO_INITIAL_ADMIN_EMAIL` | `initial_admin_email` | - | Admin user email |
| `SSSO_INITIAL_ADMIN_PASSWORD` | `initial_admin_password` | - | Admin user password |
| `SSSO_INITIAL_ADMIN_FIRST_NAME` | `initial_admin_first_name` | `Admin` | Admin first name |
| `SSSO_INITIAL_ADMIN_LAST_NAME` | `initial_admin_last_name` | `User` | Admin last name |
| `SSSO_INITIAL_ADMIN_CLIENT_SECRET` | `initial_admin_client_secret` | - | Admin client secret |

## External Login UI

| Environment Variable | Config Key | Default | Description |
|---------------------|------------|---------|-------------|
| `SSSO_NEXTJS_LOGIN_URL` | `nextjs_login_url` | - | External Next.js login UI URL |

## Email Service (Resend)

| Environment Variable | Config Key | Default | Description |
|---------------------|------------|---------|-------------|
| `SSSO_RESEND_API_KEY` | `resend_api_key` | - | Resend API key |
| `SSSO_FROM_EMAIL` | `from_email` | - | Sender email address |
| `SSSO_NEXT_PUBLIC_BASE_URL` | `next_public_base_url` | - | Base URL for email links |

## SMS Service (Twilio)

| Environment Variable | Config Key | Default | Description |
|---------------------|------------|---------|-------------|
| `SSSO_TWILIO_ACCOUNT_SID` | `twilio_account_sid` | - | Twilio account SID |
| `SSSO_TWILIO_AUTH_TOKEN` | `twilio_auth_token` | - | Twilio auth token |
| `SSSO_TWILIO_PHONE_NUMBER` | `twilio_phone_number` | - | Twilio phone number |

## Push Notifications (Firebase)

| Environment Variable | Config Key | Default | Description |
|---------------------|------------|---------|-------------|
| `SSSO_FIREBASE_PROJECT_ID` | `firebase_project_id` | - | Firebase project ID |
| `SSSO_FIREBASE_CREDENTIALS_PATH` | `firebase_credentials_path` | - | Path to Firebase credentials JSON |

## CORS Configuration

| Environment Variable | Config Key | Default | Description |
|---------------------|------------|---------|-------------|
| `SSSO_ALLOWED_ORIGINS` | `allowed_origins` | `["*"]` | Allowed CORS origins (comma-separated) |

**Example:**

```bash
SSSO_ALLOWED_ORIGINS=https://app.example.com,https://admin.example.com
```

## Rate Limiting

| Environment Variable | Config Key | Default | Description |
|---------------------|------------|---------|-------------|
| `SSSO_RATE_LIMIT_MAX_ATTEMPTS` | `rate_limit_max_attempts` | `5` | Max login attempts before lockout |
| `SSSO_RATE_LIMIT_LOCKOUT_DURATION` | `rate_limit_lockout_duration` | `15m` | Account lockout duration |

## Brand Customization

| Environment Variable | Config Key | Default | Description |
|---------------------|------------|---------|-------------|
| `SSSO_BRAND_LOGO_URL` | `brand_logo_url` | - | Custom logo URL |
| `SSSO_BRAND_ORGANIZATION_NAME` | `brand_organization_name` | - | Organization name |
| `SSSO_BRAND_PRIMARY_COLOR` | `brand_primary_color` | - | Primary brand color |

## OpenTelemetry Tracing

| Environment Variable | Config Key | Default | Description |
|---------------------|------------|---------|-------------|
| `SSSO_TRACING_ENABLED` | `tracing_enabled` | `false` | Enable OpenTelemetry tracing |
| `SSSO_TRACING_OTLP_ENDPOINT` | `tracing_otlp_endpoint` | - | OTLP collector endpoint |

## Complete Configuration File Example

```yaml
# sso_config.yaml - Complete configuration example

# ============================================
# Core Server Configuration
# ============================================
http_addr: "0.0.0.0:8080"
mgmt_http_addr: ":5000"
log_level: "info"
json_log: true
issuer_url: "https://sso.example.com"
default_redirect_uri: "https://app.example.com/callback"

# ============================================
# Database Configuration
# ============================================
mongo_uri: "mongodb://user:pass@mongo:27017/shadow_sso?authSource=admin"
mongo_db_name: "shadow_sso"
storage_backend: "mongodb"  # or "dts"

# ============================================
# DTS Configuration (when using DTS backend)
# ============================================
dts_client_address: "ssso-dts:50051"
dts_connect_timeout: "5s"

# ============================================
# Security Configuration
# ============================================
signing_key_path: "/etc/sso/keys/private.pem"
config_encryption_key: "your-32-byte-hex-encryption-key-here"
key_rotation_interval: "24h"

# ============================================
# Token Configuration
# ============================================
access_token_ttl: "1h"
refresh_token_ttl: "720h"
token_cache_default_ttl: "1h"

# ============================================
# Initial Admin Setup
# ============================================
initial_admin_enabled: true
initial_admin_email: "admin@example.com"
initial_admin_password: "change-me-immediately"
initial_admin_first_name: "Admin"
initial_admin_last_name: "User"

# ============================================
# External Login UI
# ============================================
nextjs_login_url: "https://login.example.com"

# ============================================
# Email Service (Resend)
# ============================================
resend_api_key: "re_your_api_key"
from_email: "noreply@example.com"
next_public_base_url: "https://app.example.com"

# ============================================
# SMS Service (Twilio)
# ============================================
twilio_account_sid: "ACxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
twilio_auth_token: "your_auth_token"
twilio_phone_number: "+1234567890"

# ============================================
# Push Notifications (Firebase)
# ============================================
firebase_project_id: "your-firebase-project"
firebase_credentials_path: "/etc/sso/firebase/credentials.json"

# ============================================
# CORS Configuration
# ============================================
allowed_origins:
  - "https://app.example.com"
  - "https://admin.example.com"

# ============================================
# Rate Limiting
# ============================================
rate_limit_max_attempts: 5
rate_limit_lockout_duration: "15m"

# ============================================
# Brand Customization
# ============================================
brand_logo_url: "https://example.com/logo.png"
brand_organization_name: "Example Corp"
brand_primary_color: "#0066cc"

# ============================================
# OpenTelemetry Tracing
# ============================================
tracing_enabled: true
tracing_otlp_endpoint: "http://tempo.observability:4317"
```

## Helm Chart Values

For Kubernetes deployments, see the [Kubernetes Deployment Guide](/deployment/kubernetes) for Helm values reference.

## Troubleshooting Configuration

### Common Configuration Errors

| Error | Cause | Solution |
|-------|-------|----------|
| `signing_key_path is required` | No signing key configured | Set `SSSO_SIGNING_KEY_PATH` |
| `config_encryption_key is required` | Missing encryption key | Set `SSSO_CONFIG_ENCRYPTION_KEY` |
| `mongo connection failed` | MongoDB unreachable | Check `SSSO_MONGO_URI` and network |
| `invalid storage_backend` | Invalid backend type | Use `mongodb` or `dts` |

### Debug Configuration

Enable debug logging to see loaded configuration:

```bash
SSSO_LOG_LEVEL=debug ssso
```

## Next Steps

- [Deployment Guide](/deployment/docker) - Deploy with your configuration
- [Security Best Practices](/operations/security) - Secure your deployment
- [Troubleshooting](/troubleshooting/common-issues) - Fix common issues
