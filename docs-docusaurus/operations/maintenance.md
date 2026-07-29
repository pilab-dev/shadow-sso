---
id: maintenance
title: Maintenance & Backup
sidebar_label: Maintenance
---

# Maintenance & Backup

Guide for maintaining, backing up, and recovering Shadow SSO deployments.

## Backup Strategy

### MongoDB Backup

#### Logical Backup (mongodump)

```bash
# Full database backup
mongodump --uri="mongodb://user:pass@mongo:27017/shadow_sso" \
  --archive=backup-$(date +%Y%m%d-%H%M%S).gz --gzip

# Specific collections
mongodump --uri="mongodb://user:pass@mongo:27017/shadow_sso" \
  --collection=users --archive=users-backup.gz --gzip
```

#### Physical Backup (Filesystem)

For MongoDB replica sets, use filesystem snapshots:

```bash
# Stop writes temporarily
mongo --eval 'db.fsyncLock()'

# Take filesystem snapshot
# (Use your storage system's snapshot mechanism)

# Resume writes
mongo --eval 'db.fsyncUnlock()'
```

#### Automated Backup Script

```bash
#!/bin/bash
# backup-sso.sh

BACKUP_DIR="/backups/sso"
DATE=$(date +%Y%m%d-%H%M%S)
RETENTION_DAYS=30

# Create backup directory
mkdir -p "$BACKUP_DIR"

# Backup MongoDB
mongodump --uri="$SSSO_MONGO_URI" \
  --archive="$BACKUP_DIR/mongo-$DATE.gz" --gzip

# Backup signing keys (if not in K8s secrets)
if [ -d "/etc/sso/keys" ]; then
  tar -czf "$BACKUP_DIR/keys-$DATE.tar.gz" /etc/sso/keys/
fi

# Cleanup old backups
find "$BACKUP_DIR" -type f -mtime +$RETENTION_DAYS -delete

echo "Backup completed: $DATE"
```

### DTS Backup

The DTS service uses BBoltDB. Backup the database file:

```bash
# Stop DTS service
kubectl scale deployment ssso-dts --replicas=0

# Copy database file
kubectl cp ssso-dts-xxx:/data/dts.db ./dts-backup.db

# Restart DTS
kubectl scale deployment ssso-dts --replicas=1
```

### Configuration Backup

Backup configuration files and secrets:

```bash
# Kubernetes secrets
kubectl get secret sso-signing-key -o yaml > signing-key-secret.yaml
kubectl get secret ssso-config -o yaml > config-secret.yaml
kubectl get secret ssso-initial-admin-credentials -o yaml > admin-secret.yaml

# Helm values
helm get values ssso-backend -n shadow-sso > helm-values.yaml
```

## Restore Procedures

### Restore MongoDB

```bash
# Restore from archive
mongorestore --uri="mongodb://user:pass@mongo:27017/shadow_sso" \
  --archive=backup-20240101-120000.gz --gzip

# Restore specific collection
mongorestore --uri="mongodb://user:pass@mongo:27017/shadow_sso" \
  --collection=users --archive=users-backup.gz --gzip
```

### Restore DTS

```bash
# Stop DTS
kubectl scale deployment ssso-dts --replicas=0

# Restore database
kubectl cp ./dts-backup.db ssso-dts-xxx:/data/dts.db

# Restart DTS
kubectl scale deployment ssso-dts --replicas=1
```

## Key Rotation

### JWKS Key Rotation

Shadow SSO automatically rotates JWKS keys based on `SSSO_KEY_ROTATION_INTERVAL`.

**Manual rotation:**

1. Generate new signing key:
```bash
openssl genrsa -out new-private.pem 2048
```

2. Update the secret:
```bash
kubectl create secret generic sso-signing-key \
  --from-file=private.pem=./new-private.pem \
  -n shadow-sso --dry-run=client -o yaml | kubectl apply -f -
```

3. Restart pods to pick up the new key:
```bash
kubectl rollout restart deployment/ssso-backend -n shadow-sso
```

### Encryption Key Rotation

:::warning
Rotating the encryption key requires re-encrypting all sensitive configuration data.
:::

1. Generate new key:
```bash
NEW_KEY=$(openssl rand -hex 32)
```

2. Update configuration and restart
3. Re-encrypt sensitive data with the new key

## Database Maintenance

### MongoDB Indexes

Shadow SSO creates indexes automatically. Verify indexes:

```bash
mongo --eval 'db.users.getIndexes()'
mongo --eval 'db.clients.getIndexes()'
```

### Collection Statistics

```bash
mongo --eval 'db.users.stats()'
mongo --eval 'db.sessions.stats()'
```

### Cleanup Expired Data

Sessions and tokens expire automatically. Manual cleanup:

```bash
# Remove expired sessions
mongo --eval 'db.sessions.deleteMany({expiresAt: {$lt: new Date()}})'

# Remove expired tokens
mongo --eval 'db.tokens.deleteMany({expiresAt: {$lt: new Date()}})'
```

## Certificate Management

### TLS Certificates

For Kubernetes with cert-manager:

```yaml
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: sso-tls
  namespace: shadow-sso
spec:
  secretName: sso-tls
  issuerRef:
    name: letsencrypt-prod
    kind: ClusterIssuer
  dnsNames:
    - sso.example.com
```

### Signing Key Backup

Always backup signing keys before rotation:

```bash
kubectl get secret sso-signing-key -o jsonpath='{.data.private\.pem}' | base64 -d > signing-key-backup.pem
```

## Monitoring Health

### Health Check Endpoints

| Endpoint | Purpose | Expected Response |
|----------|---------|-------------------|
| `/healthz` | Liveness probe | `{"status":"ok"}` |
| `/readyz` | Readiness probe | `{"status":"ok"}` |
| `/metrics` | Prometheus metrics | Prometheus format |

### Kubernetes Health Checks

```bash
# Check pod health
kubectl get pods -n shadow-sso

# Check readiness
kubectl describe pod <pod-name> -n shadow-sso | grep -A5 Conditions

# Check events
kubectl get events -n shadow-sso --sort-by='.lastTimestamp'
```

## Upgrade Procedures

### Docker Compose Upgrade

```bash
# Pull new image
docker compose pull

# Rolling restart
docker compose up -d --no-deps ssso

# Verify
docker compose ps
curl http://localhost:5000/healthz
```

### Kubernetes Upgrade

```bash
# Update Helm values
helm upgrade ssso-backend ./helm/ssso-backend \
  --set image.tag=v1.2.0 \
  -n shadow-sso

# Monitor rollout
kubectl rollout status deployment/ssso-backend -n shadow-sso

# Verify
kubectl get pods -n shadow-sso
```

### Rollback

```bash
# Kubernetes
kubectl rollout undo deployment/ssso-backend -n shadow-sso

# Docker Compose
docker compose down
docker compose up -d
```

## Performance Tuning

### MongoDB Tuning

```bash
# Check connection pool
mongo --eval 'db.serverStatus().connections'

# Check slow queries
mongo --eval 'db.setProfilingLevel(1, {slowms: 100})'
```

### Application Tuning

| Setting | Recommendation |
|---------|----------------|
| `SSSO_LOG_LEVEL` | `info` for production |
| `SSSO_JSON_LOG` | `true` for production |
| Connection pool | Monitor and adjust MongoDB pool size |

## Disaster Recovery

### Complete Recovery

1. **Restore MongoDB** from latest backup
2. **Restore signing keys** from backup
3. **Restore configuration** secrets
4. **Redeploy** application
5. **Verify** health endpoints
6. **Test** login flow

### Recovery Time Objectives

| Component | RTO | RPO |
|-----------|-----|-----|
| MongoDB | 1 hour | 15 minutes |
| DTS | 30 minutes | 10 minutes |
| Application | 15 minutes | N/A (stateless) |

## Next Steps

- [Monitoring](/operations/monitoring) - Set up observability
- [Security](/operations/security) - Security best practices
- [Troubleshooting](/troubleshooting/common-issues) - Common issues
