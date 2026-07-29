---
id: kubernetes
title: Kubernetes Deployment
sidebar_label: Kubernetes
---

# Kubernetes Deployment

Deploy Shadow SSO on Kubernetes using Helm for production-grade, scalable deployments.

## Overview

Kubernetes deployment provides:
- High availability with multiple replicas
- Automatic scaling
- Rolling updates
- Health checks and self-healing
- Network policies
- TLS termination via Ingress

## Prerequisites

- Kubernetes 1.24+
- Helm 3.x
- `kubectl` configured with cluster access
- MongoDB instance (external recommended)
- Container registry access (GHCR)

## Architecture

```
                    +-------------------+
                    |   Ingress/TLS     |
                    +--------+----------+
                             |
                    +--------v----------+
                    |   Load Balancer   |
                    +--------+----------+
                             |
              +--------------+--------------+
              |              |              |
     +--------v---+  +------v-----+  +-----v-------+
     |  SSSO Pod  |  |  SSSO Pod  |  |  SSSO Pod   |
     |  (Replica) |  |  (Replica) |  |  (Replica)  |
     +--------+---+  +------+-----+  +-----+-------+
              |              |              |
              +--------------+--------------+
                             |
                    +--------v----------+
                    |   MongoDB         |
                    |   (External)      |
                    +-------------------+
```

## Installation

### 1. Add Helm Repository (When Published)

```bash
helm repo add shadow-sso https://charts.pilab.dev
helm repo update
```

### 2. Or Install from Local Chart

```bash
git clone https://github.com/pilab-dev/shadow-sso.git
cd shadow-sso
```

## Required Kubernetes Secrets

Before deploying, create the required secrets:

### 1. Signing Key Secret

```bash
# Generate RSA key
openssl genrsa -out private.pem 2048

# Create secret
kubectl create secret generic sso-signing-key \
  --from-file=private.pem=./private.pem \
  -n shadow-sso
```

### 2. Admin Credentials Secret

```bash
kubectl create secret generic ssso-initial-admin-credentials \
  --from-literal=SSSO_INITIAL_ADMIN_EMAIL=admin@example.com \
  --from-literal=SSSO_INITIAL_ADMIN_PASSWORD='<strong-password>' \
  --from-literal=SSSO_INITIAL_ADMIN_FIRST_NAME=Admin \
  --from-literal=SSSO_INITIAL_ADMIN_LAST_NAME=User \
  -n shadow-sso
```

### 3. MongoDB Connection Secret

```bash
kubectl create secret generic ssso-config \
  --from-literal=SSSO_MONGO_URI='mongodb://user:pass@mongo-host:27017/shadow_sso?authSource=admin' \
  -n shadow-sso
```

### 4. GHCR Pull Secret (If Private)

```bash
kubectl create secret docker-registry ghcr-secret \
  --docker-server=ghcr.io \
  --docker-username=<your-github-username> \
  --docker-password=<your-github-token> \
  -n shadow-sso
```

## Helm Values

### Development Values

```yaml
# values-dev.yaml
replicaCount: 1

image:
  repository: ghcr.io/pilab-dev/shadow-sso-backend
  pullPolicy: IfNotPresent
  tag: "latest"

config:
  SSSO_LOG_LEVEL: "debug"
  SSSO_JSON_LOG: "false"
  SSSO_ISSUER_URL: "http://localhost:8080"
  SSSO_SIGNING_KEY_PATH: "/etc/sso/keys/private.pem"

initialAdmin:
  enabled: true
  createSecret: true
  credentials:
    email: "admin@example.com"
    password: "dev-password"

signingKeySecretName: "sso-signing-key"
createSigningKeySecret: false

resources:
  limits:
    cpu: 200m
    memory: 256Mi
  requests:
    cpu: 100m
    memory: 128Mi

ingress:
  enabled: false

mongodb:
  enabled: false
```

### Production Values

```yaml
# values-production.yaml
replicaCount: 2

image:
  repository: ghcr.io/pilab-dev/shadow-sso-backend
  pullPolicy: Always
  tag: "v1"

imagePullSecrets:
  - name: ghcr-secret

podSecurityContext:
  fsGroup: 1001
  runAsUser: 1001
  runAsNonRoot: true

securityContext:
  allowPrivilegeEscalation: false
  capabilities:
    drop:
    - ALL
  readOnlyRootFilesystem: true
  seccompProfile:
    type: RuntimeDefault

service:
  type: ClusterIP
  port: 8080

ingress:
  enabled: true
  className: "nginx"
  annotations:
    cert-manager.io/cluster-issuer: letsencrypt-prod
    nginx.ingress.kubernetes.io/ssl-redirect: "true"
  hosts:
    - host: sso.example.com
      paths:
        - path: /
          pathType: Prefix
  tls:
    - secretName: sso-tls
      hosts:
        - sso.example.com

config:
  SSSO_LOG_LEVEL: "info"
  SSSO_JSON_LOG: "true"
  SSSO_ISSUER_URL: "https://sso.example.com"
  SSSO_SIGNING_KEY_PATH: "/etc/sso/keys/private.pem"
  SSSO_KEY_ROTATION_INTERVAL: "24h"

initialAdmin:
  enabled: true
  createSecret: false
  secretName: "ssso-initial-admin-credentials"

signingKeySecretName: "sso-signing-key"
createSigningKeySecret: false

resources:
  limits:
    cpu: 500m
    memory: 512Mi
  requests:
    cpu: 200m
    memory: 256Mi

autoscaling:
  enabled: true
  minReplicas: 2
  maxReplicas: 5
  targetCPUUtilizationPercentage: 80

networkPolicy:
  enabled: true

# OpenTelemetry tracing
tracing:
  enabled: true
  otlpEndpoint: "http://tempo.observability:4317"
  serviceName: "shadow-sso"

extraEnvFrom:
  - secretRef:
      name: ssso-config
```

## Deploy

### Install with Helm

```bash
# Development
helm install ssso-backend ./helm/ssso-backend \
  -f values-dev.yaml \
  -n shadow-sso \
  --create-namespace

# Production
helm install ssso-backend ./helm/ssso-backend \
  -f values-production.yaml \
  -n shadow-sso \
  --create-namespace
```

### Upgrade

```bash
helm upgrade ssso-backend ./helm/ssso-backend \
  -f values-production.yaml \
  -n shadow-sso
```

### Uninstall

```bash
helm uninstall ssso-backend -n shadow-sso
```

## Verification

### Check Deployment Status

```bash
# Check pods
kubectl get pods -n shadow-sso

# Check services
kubectl get svc -n shadow-sso

# Check ingress
kubectl get ingress -n shadow-sso

# Check deployment details
kubectl describe deployment ssso-backend -n shadow-sso
```

### Test Health Endpoints

```bash
# Port forward for testing
kubectl port-forward svc/ssso-backend 8080:8080 -n shadow-sso

# Test health
curl http://localhost:8080/healthz

# Test OIDC discovery
curl http://localhost:8080/.well-known/openid-configuration
```

### View Logs

```bash
# Stream logs
kubectl logs -f deployment/ssso-backend -n shadow-sso

# View last 100 lines
kubectl logs --tail=100 deployment/ssso-backend -n shadow-sso

# View logs from specific pod
kubectl logs -f ssso-backend-abc123-xyz -n shadow-sso
```

## Scaling

### Manual Scaling

```bash
kubectl scale deployment ssso-backend --replicas=3 -n shadow-sso
```

### Horizontal Pod Autoscaler

The Helm chart includes HPA support:

```yaml
autoscaling:
  enabled: true
  minReplicas: 2
  maxReplicas: 10
  targetCPUUtilizationPercentage: 80
  targetMemoryUtilizationPercentage: 80
```

## Rolling Updates

### Update Image Tag

```bash
helm upgrade ssso-backend ./helm/ssso-backend \
  --set image.tag=v1.2.0 \
  -n shadow-sso
```

### Monitor Rollout

```bash
kubectl rollout status deployment/ssso-backend -n shadow-sso

# View rollout history
kubectl rollout history deployment/ssso-backend -n shadow-sso

# Rollback if needed
kubectl rollout undo deployment/ssso-backend -n shadow-sso
```

## Network Policies

Enable network policies for enhanced security:

```yaml
networkPolicy:
  enabled: true
  egress:
    mongoCIDRs:
      - "10.0.0.0/8"  # Restrict MongoDB access
```

## Monitoring

### Prometheus Metrics

The application exposes Prometheus metrics at `/metrics`:

```yaml
# ServiceMonitor for Prometheus Operator
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: ssso-backend
  namespace: shadow-sso
spec:
  selector:
    matchLabels:
      app.kubernetes.io/instance: ssso-backend
  endpoints:
    - port: http
      path: /metrics
```

### OpenTelemetry Tracing

Enable distributed tracing:

```yaml
tracing:
  enabled: true
  otlpEndpoint: "http://tempo.observability:4317"
  serviceName: "shadow-sso"
```

## Troubleshooting

### Pod Not Starting

```bash
# Check pod events
kubectl describe pod <pod-name> -n shadow-sso

# Check init container logs
kubectl logs <pod-name> -c init -n shadow-sso

# Check main container logs
kubectl logs <pod-name> -n shadow-sso
```

### MongoDB Connection Issues

```bash
# Test MongoDB connectivity from pod
kubectl exec -it <pod-name> -n shadow-sso -- nc -zv mongo-host 27017

# Check secret
kubectl get secret ssso-config -n shadow-sso -o yaml
```

### Image Pull Errors

```bash
# Verify image pull secret
kubectl get secret ghcr-secret -n shadow-sso

# Test pull manually
kubectl run test --image=ghcr.io/pilab-dev/shadow-sso-backend:v1 -n shadow-sso
```

## Next Steps

- [Configuration Reference](/configuration/reference) - All Helm values
- [Monitoring](/operations/monitoring) - Set up observability
- [Maintenance](/operations/maintenance) - Backup and recovery
