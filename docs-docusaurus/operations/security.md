---
id: security
title: Security Best Practices
sidebar_label: Security
---

# Security Best Practices

Comprehensive security guide for deploying and operating Shadow SSO.

## Security Architecture

Shadow SSO implements defense-in-depth with multiple security layers:

```
+--------------------------------------------------+
|  Layer 7: Network Security (TLS, NetworkPolicy)  |
+--------------------------------------------------+
|  Layer 6: Application Security (RBAC, CORS)      |
+--------------------------------------------------+
|  Layer 5: Token Security (JWT, PKCE, Rotation)   |
+--------------------------------------------------+
|  Layer 4: Authentication (MFA, Rate Limiting)    |
+--------------------------------------------------+
|  Layer 3: Data Encryption (AES-256, bcrypt)      |
+--------------------------------------------------+
|  Layer 2: Infrastructure (Non-root, ReadOnly FS) |
+--------------------------------------------------+
|  Layer 1: Supply Chain (Signed images, SBOM)     |
+--------------------------------------------------+
```

## Authentication Security

### Password Policy

Shadow SSO uses bcrypt for password hashing:

```bash
# Default cost factor: 12
# Adjust via SSSO_SECURITY_PASSWORD_HASH_COST
```

**Recommendations:**
- Enforce minimum 12-character passwords
- Use cost factor 12 or higher
- Implement password complexity requirements at the application level

### Multi-Factor Authentication

Enable MFA for sensitive operations:

| Method | Use Case | Security Level |
|--------|----------|----------------|
| TOTP | General MFA | High |
| Push MFA | Mobile users | High |
| Email MFA | Backup method | Medium |
| SMS MFA | Legacy support | Low |
| Recovery Codes | Account recovery | High |

### Account Lockout

Configure rate limiting to prevent brute force:

```bash
SSSO_RATE_LIMIT_MAX_ATTEMPTS=5
SSSO_RATE_LIMIT_LOCKOUT_DURATION=15m
```

## Token Security

### JWT Configuration

| Setting | Recommendation |
|---------|----------------|
| Access token TTL | 15-60 minutes |
| Refresh token TTL | 7-30 days |
| Signing algorithm | RS256 (minimum) |
| Key rotation | Every 24 hours |

### PKCE (Proof Key for Code Exchange)

PKCE is enabled by default and required for public clients:

```bash
# PKCE is always enabled
# Supported methods: S256 (recommended)
```

### Token Rotation

Enable refresh token rotation:

```yaml
# Tokens are automatically rotated on refresh
# Old refresh tokens are invalidated after use
```

## Data Encryption

### At Rest

| Data | Encryption |
|------|------------|
| Passwords | bcrypt (cost 12) |
| Sensitive config | AES-256-GCM |
| MongoDB data | Enable MongoDB encryption at rest |
| DTS data | BBoltDB (filesystem encryption recommended) |

### In Transit

| Connection | Encryption |
|------------|------------|
| Client ↔ SSO | TLS 1.2+ (HTTPS) |
| SSO ↔ MongoDB | TLS (recommended) |
| SSO ↔ DTS | mTLS (recommended) |

### Encryption Key Management

```bash
# Generate encryption key
SSSO_CONFIG_ENCRYPTION_KEY=$(openssl rand -hex 32)

# Store securely (Kubernetes secret, Vault, etc.)
kubectl create secret generic sso-encryption-key \
  --from-literal=key=$SSSO_CONFIG_ENCRYPTION_KEY
```

## Network Security

### TLS Configuration

```yaml
# Ingress with TLS
ingress:
  enabled: true
  annotations:
    cert-manager.io/cluster-issuer: letsencrypt-prod
    nginx.ingress.kubernetes.io/ssl-redirect: "true"
    nginx.ingress.kubernetes.io/ssl-passthrough: "false"
  tls:
    - secretName: sso-tls
      hosts:
        - sso.example.com
```

### CORS Configuration

Restrict allowed origins:

```bash
# Don't use wildcard in production
SSSO_ALLOWED_ORIGINS=https://app.example.com,https://admin.example.com
```

### Network Policies (Kubernetes)

```yaml
networkPolicy:
  enabled: true
  egress:
    mongoCIDRs:
      - "10.0.0.0/8"  # Restrict MongoDB access
```

## Container Security

### Non-Root User

The Docker image runs as non-root:

```dockerfile
USER appuser  # UID 1001
```

### Read-Only Filesystem

```yaml
securityContext:
  readOnlyRootFilesystem: true
  allowPrivilegeEscalation: false
  capabilities:
    drop:
      - ALL
```

### Resource Limits

```yaml
resources:
  limits:
    cpu: 500m
    memory: 512Mi
  requests:
    cpu: 200m
    memory: 256Mi
```

## Secret Management

### Kubernetes Secrets

```bash
# Create secrets
kubectl create secret generic sso-signing-key \
  --from-file=private.pem=./private.pem

kubectl create secret generic ssso-config \
  --from-literal=SSSO_MONGO_URI='mongodb://...'

# Use sealed secrets for GitOps
# https://github.com/bitnami-labs/sealed-secrets
```

### External Secret Managers

| Manager | Integration |
|---------|-------------|
| HashiCorp Vault | Via Vault Agent Injector |
| AWS Secrets Manager | Via External Secrets Operator |
| Azure Key Vault | Via External Secrets Operator |
| GCP Secret Manager | Via External Secrets Operator |

### Secret Rotation

| Secret | Rotation Frequency | Method |
|--------|-------------------|--------|
| Signing key | 24h (automatic) | JWKS rotation |
| Encryption key | 90 days | Manual + re-encrypt |
| MongoDB password | 90 days | Update secret + restart |
| Admin password | 90 days | Via GraphQL/CLI |

## OAuth2/OIDC Security

### Client Authentication

| Client Type | Authentication | Use Case |
|-------------|---------------|----------|
| Confidential | Client secret / JWT | Server-side apps |
| Public | PKCE | Mobile/SPA apps |

### Grant Types

| Grant Type | Security Level | Use Case |
|------------|---------------|----------|
| Authorization Code + PKCE | High | Web/mobile apps |
| Client Credentials | High | Machine-to-machine |
| Device Code | Medium | Input-constrained devices |
| Password | Low | Legacy (discouraged) |

### Scope Validation

Always validate requested scopes:

```go
// Only grant scopes the client is authorized for
// Never grant admin scopes to public clients
```

## Audit Logging

### Enable Audit Logs

```bash
SSSO_LOG_LEVEL=info
SSSO_JSON_LOG=true
```

### Log Events

| Event | Log Level | Fields |
|-------|-----------|--------|
| Login success | INFO | user_id, client_id, ip |
| Login failure | WARN | email, client_id, ip, reason |
| Token issued | INFO | user_id, client_id, scope |
| Token revoked | INFO | user_id, token_id |
| Password change | INFO | user_id |
| MFA enabled/disabled | INFO | user_id, method |

### Log Retention

```bash
# Configure log retention based on compliance requirements
# Typical: 90 days for security, 7 years for financial
```

## Compliance

### OWASP Top 10

| Risk | Mitigation |
|------|------------|
| A01: Broken Access Control | RBAC, scope validation |
| A02: Cryptographic Failures | TLS 1.2+, bcrypt, AES-256 |
| A03: Injection | Parameterized queries, input validation |
| A04: Insecure Design | PKCE, token rotation |
| A05: Security Misconfiguration | Security headers, defaults |
| A06: Vulnerable Components | Dependabot, regular updates |
| A07: Authentication Failures | MFA, rate limiting |
| A08: Software & Data Integrity | Signed images, SBOM |
| A09: Security Logging | Audit logs, alerting |
| A10: SSRF | URL validation, network policies |

### GDPR Considerations

- User data stored in MongoDB (EU region recommended)
- Right to erasure: Delete user via GraphQL API
- Data portability: Export user data via API
- Consent management: Track via user attributes

## Security Checklist

### Pre-Deployment

- [ ] Generate strong signing key (2048+ bit RSA)
- [ ] Set strong encryption key (32 bytes)
- [ ] Configure TLS certificates
- [ ] Set strong admin password
- [ ] Restrict CORS origins
- [ ] Enable rate limiting
- [ ] Configure network policies

### Production

- [ ] Enable JSON logging
- [ ] Set log level to `info`
- [ ] Enable audit logging
- [ ] Configure monitoring/alerting
- [ ] Set up secret rotation
- [ ] Enable MFA for admin accounts
- [ ] Review OAuth client configurations
- [ ] Test disaster recovery

### Ongoing

- [ ] Review security advisories
- [ ] Update dependencies monthly
- [ ] Rotate secrets quarterly
- [ ] Conduct security audits annually
- [ ] Review access logs weekly

## Incident Response

### Compromised Signing Key

1. Generate new signing key immediately
2. Update Kubernetes secret
3. Restart all pods
4. Invalidate all existing tokens
5. Notify affected clients

### Compromised Admin Account

1. Disable the admin account
2. Reset the password
3. Review audit logs for unauthorized actions
4. Rotate any tokens issued by the account

### Data Breach

1. Isolate affected systems
2. Assess scope of breach
3. Notify affected users (GDPR: 72 hours)
4. Rotate all secrets
5. Conduct forensic analysis

## Next Steps

- [Troubleshooting](/troubleshooting/common-issues) - Common security issues
- [Maintenance](/operations/maintenance) - Key rotation procedures
- [Monitoring](/operations/monitoring) - Security monitoring
