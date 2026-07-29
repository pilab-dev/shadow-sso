---
id: common-issues
title: Common Issues
sidebar_label: Troubleshooting
---

# Troubleshooting Guide

Common issues and their solutions when deploying and operating Shadow SSO.

## Startup Issues

### Server Won't Start

**Symptom:** Container exits immediately or crashes on startup.

**Diagnosis:**

```bash
# View logs
docker logs ssso
kubectl logs deployment/ssso-backend -n shadow-sso

# Check exit code
docker inspect --format='{{.State.ExitCode}}' ssso
```

**Common Causes:**

| Error | Cause | Solution |
|-------|-------|----------|
| `signing_key_path is required` | No signing key configured | Set `SSSO_SIGNING_KEY_PATH` or generate key |
| `config_encryption_key is required` | Missing encryption key | Set `SSSO_CONFIG_ENCRYPTION_KEY` |
| `mongo connection refused` | MongoDB unreachable | Check `SSSO_MONGO_URI` and network |
| `permission denied: /etc/sso/keys` | Wrong file permissions | `chmod 644` on key files |
| `address already in use` | Port conflict | Change `SSSO_HTTP_ADDR` or free port |

### MongoDB Connection Failed

**Symptom:** `failed to connect to MongoDB: connection refused`

**Diagnosis:**

```bash
# Test MongoDB connectivity
docker exec ssso nc -zv mongo 27017
kubectl exec -it <pod> -- nc -zv mongo-host 27017

# Check MongoDB is running
docker ps | grep mongo
kubectl get pods -l app=mongodb

# Verify connection string
echo $SSSO_MONGO_URI
```

**Solutions:**

1. **Wrong hostname:** Use correct MongoDB hostname
   ```bash
   # Docker Compose
   SSSO_MONGO_URI=mongodb://mongo:27017
   
   # Kubernetes (same namespace)
   SSSO_MONGO_URI=mongodb://mongodb-service:27017
   ```

2. **Authentication failed:** Check credentials
   ```bash
   SSSO_MONGO_URI=mongodb://user:pass@mongo:27017/shadow_sso?authSource=admin
   ```

3. **Network policy blocking:** Allow egress to MongoDB
   ```yaml
   networkPolicy:
     enabled: true
     egress:
       mongoCIDRs:
         - "10.0.0.0/8"
   ```

### Health Check Failing

**Symptom:** Pod marked unhealthy, restarts repeatedly.

**Diagnosis:**

```bash
# Check health endpoint
curl http://localhost:5000/healthz

# Check pod events
kubectl describe pod <pod> -n shadow-sso
```

**Common Causes:**

1. **Slow startup:** Increase `initialDelaySeconds`
   ```yaml
   livenessProbe:
     initialDelaySeconds: 60  # Increase from default 30
   ```

2. **MongoDB slow:** Check database performance
   ```bash
   mongo --eval 'db.serverStatus()'
   ```

3. **Resource exhaustion:** Increase resource limits
   ```yaml
   resources:
     limits:
       memory: 512Mi  # Increase
   ```

## Authentication Issues

### Login Failed

**Symptom:** `invalid email or password` error.

**Diagnosis:**

```bash
# Check user exists
ssoctl user get user@example.com

# Check user status
ssoctl user list | grep user@example.com
```

**Common Causes:**

| Cause | Solution |
|-------|----------|
| Wrong credentials | Verify email/password |
| Account locked | Wait for lockout duration or unlock via admin |
| Account inactive | Activate account: `ssoctl user activate <id>` |
| MFA required | Complete MFA flow after password |

### Token Expired

**Symptom:** `token expired` or `invalid token` errors.

**Diagnosis:**

```bash
# Check token expiry
ssoctl auth status

# Check token TTL settings
echo $SSSO_ACCESS_TOKEN_TTL
```

**Solutions:**

1. **Refresh token:** Use refresh token to get new access token
2. **Increase TTL:** Adjust `SSSO_ACCESS_TOKEN_TTL`
3. **Check clock sync:** Ensure server time is correct

### MFA Not Working

**Symptom:** TOTP codes rejected or push notifications not received.

**Diagnosis:**

```bash
# Check MFA status
ssoctl user 2fa status <user-id>

# Check push notification service
kubectl logs deployment/ssso-backend | grep firebase
```

**Common Causes:**

| Issue | Solution |
|-------|----------|
| TOTP time drift | Sync device time |
| Push not configured | Check Firebase credentials |
| Email not received | Check Resend API key |
| SMS not received | Check Twilio configuration |

## OAuth2/OIDC Issues

### Authorization Code Invalid

**Symptom:** `invalid authorization code` during token exchange.

**Common Causes:**

1. **Code expired:** Authorization codes expire in 10 minutes
2. **Code already used:** Codes are single-use
3. **Wrong client:** Code must be exchanged by same client

**Solution:** Request new authorization code.

### Redirect URI Mismatch

**Symptom:** `invalid redirect_uri` error.

**Diagnosis:**

```bash
# Check client configuration
ssoctl client get <client-id>
```

**Solution:** Ensure redirect URI exactly matches registered URI (including trailing slash).

### CORS Error

**Symptom:** Browser blocks request with CORS error.

**Diagnosis:**

```bash
# Check allowed origins
echo $SSSO_ALLOWED_ORIGINS

# Test CORS
curl -H "Origin: https://app.example.com" \
  -H "Access-Control-Request-Method: POST" \
  -X OPTIONS http://localhost:8080/oauth2/token -v
```

**Solution:** Add origin to allowed list:
```bash
SSSO_ALLOWED_ORIGINS=https://app.example.com,https://admin.example.com
```

## Performance Issues

### High Memory Usage

**Symptom:** Pod OOMKilled or memory warnings.

**Diagnosis:**

```bash
# Check memory usage
kubectl top pod -n shadow-sso

# Check Go memory stats
curl http://localhost:5000/metrics | grep go_memstats
```

**Solutions:**

1. **Increase memory limit:**
   ```yaml
   resources:
     limits:
       memory: 1Gi
   ```

2. **Check for memory leaks:** Monitor over time
3. **Reduce connection pool size** if MongoDB connections are high

### Slow Response Times

**Symptom:** API responses take >1 second.

**Diagnosis:**

```bash
# Check latency metrics
curl http://localhost:5000/metrics | grep http_request_duration

# Check MongoDB slow queries
mongo --eval 'db.setProfilingLevel(1, {slowms: 100})'
```

**Common Causes:**

| Cause | Solution |
|-------|----------|
| MongoDB slow | Add indexes, optimize queries |
| Network latency | Check network policies |
| Resource limits | Increase CPU/memory |
| Connection pool exhausted | Increase pool size |

### High CPU Usage

**Symptom:** CPU throttling or high CPU metrics.

**Diagnosis:**

```bash
kubectl top pod -n shadow-sso
```

**Solutions:**

1. **Increase CPU limit:**
   ```yaml
   resources:
     limits:
       cpu: 1000m
   ```

2. **Scale horizontally:** Increase replica count
3. **Check bcrypt cost:** Lower `SSSO_SECURITY_PASSWORD_HASH_COST` if too high

## Kubernetes Issues

### Image Pull Error

**Symptom:** `ImagePullBackOff` or `ErrImagePull`.

**Diagnosis:**

```bash
kubectl describe pod <pod> -n shadow-sso
```

**Solutions:**

1. **Private registry:** Create image pull secret
   ```bash
   kubectl create secret docker-registry ghcr-secret \
     --docker-server=ghcr.io \
     --docker-username=<user> \
     --docker-password=<token>
   ```

2. **Wrong image tag:** Verify tag exists
   ```bash
   helm upgrade --set image.tag=v1.0.0
   ```

### Pod Stuck in Pending

**Symptom:** Pod stays in `Pending` state.

**Diagnosis:**

```bash
kubectl describe pod <pod> -n shadow-sso
```

**Common Causes:**

| Cause | Solution |
|-------|----------|
| Insufficient resources | Add nodes or reduce requests |
| PVC not bound | Check storage class |
| Node selector mismatch | Update node labels |

### Rolling Update Stuck

**Symptom:** Deployment stuck during rollout.

**Diagnosis:**

```bash
kubectl rollout status deployment/ssso-backend
kubectl describe deployment ssso-backend
```

**Solutions:**

1. **Check new pod health:**
   ```bash
   kubectl logs <new-pod> -n shadow-sso
   ```

2. **Rollback:**
   ```bash
   kubectl rollout undo deployment/ssso-backend
   ```

## Data Issues

### Duplicate Users

**Symptom:** Multiple users with same email.

**Diagnosis:**

```bash
mongo --eval 'db.users.aggregate([{$group:{_id:"$email",count:{$sum:1}}},{$match:{count:{$gt:1}}}])'
```

**Solution:** Merge or delete duplicate users via GraphQL API.

### Orphaned Sessions

**Symptom:** Sessions exist for deleted users.

**Diagnosis:**

```bash
mongo --eval 'db.sessions.count({userId: {$nin: db.users.distinct("_id")}})'
```

**Solution:** Cleanup orphaned sessions:
```bash
mongo --eval 'db.sessions.deleteMany({userId: {$nin: db.users.distinct("_id")}})'
```

## Getting Help

### Collect Debug Information

```bash
# Collect logs
kubectl logs deployment/ssso-backend -n shadow-sso --tail=1000 > logs.txt

# Collect metrics
curl http://localhost:5000/metrics > metrics.txt

# Collect pod info
kubectl describe pod <pod> -n shadow-sso > pod-info.txt

# Collect events
kubectl get events -n shadow-sso --sort-by='.lastTimestamp' > events.txt
```

### Report Issues

1. **GitHub Issues:** [Report bugs](https://github.com/pilab-dev/shadow-sso/issues)
2. **Security Issues:** Email [gyula@pilab.hu](mailto:gyula@pilab.hu)
3. **Include:** Logs, metrics, configuration (redact secrets)

## Next Steps

- [Security](/operations/security) - Security best practices
- [Monitoring](/operations/monitoring) - Set up observability
- [Maintenance](/operations/maintenance) - Backup procedures
