---
id: docker
title: Docker Deployment
sidebar_label: Docker
---

# Docker Deployment

Deploy Shadow SSO using Docker for a quick, reproducible setup.

## Prerequisites

- Docker 20.10+
- MongoDB 5.0+ (can be containerized)

## Docker Image

The official Docker image is available at:

```
ghcr.io/pilab-dev/shadow-sso-backend:v1
```

### Image Details

| Property | Value |
|----------|-------|
| Base Image | `alpine:3.21` |
| User | `appuser` (non-root, UID 1001) |
| Exposed Ports | `8080` (HTTP), `5000` (Management) |
| Health Check | `curl -f http://localhost:5000/healthz` |
| Entrypoint | Auto-generates signing key if missing |

## Quick Start

### 1. Start MongoDB

```bash
docker run -d \
  --name mongodb \
  -p 27017:27017 \
  -v mongo_data:/data/db \
  mongo:7
```

### 2. Prepare Signing Key

```bash
mkdir -p ./keys
openssl genrsa -out ./keys/private.pem 2048
```

### 3. Run Shadow SSO

```bash
docker run -d \
  --name ssso \
  -p 8080:8080 \
  -p 5000:5000 \
  --network host \
  -e SSSO_MONGO_URI=mongodb://localhost:27017 \
  -e SSSO_MONGO_DB_NAME=shadow_sso \
  -e SSSO_ISSUER_URL=http://localhost:8080 \
  -e SSSO_SIGNING_KEY_PATH=/etc/sso/keys/private.pem \
  -e SSSO_INITIAL_ADMIN_ENABLED=true \
  -e SSSO_INITIAL_ADMIN_EMAIL=admin@example.com \
  -e SSSO_INITIAL_ADMIN_PASSWORD=changeme123 \
  -e SSSO_CONFIG_ENCRYPTION_KEY=$(openssl rand -hex 32) \
  -v $(pwd)/keys:/etc/sso/keys:ro \
  ghcr.io/pilab-dev/shadow-sso-backend:v1
```

## Docker Networking

### Using Docker Networks

For production, use a dedicated Docker network:

```bash
# Create network
docker network create sso-network

# Run MongoDB
docker run -d \
  --name mongodb \
  --network sso-network \
  -v mongo_data:/data/db \
  mongo:7

# Run Shadow SSO
docker run -d \
  --name ssso \
  --network sso-network \
  -p 8080:8080 \
  -p 5000:5000 \
  -e SSSO_MONGO_URI=mongodb://mongodb:27017 \
  -e SSSO_MONGO_DB_NAME=shadow_sso \
  -e SSSO_ISSUER_URL=http://localhost:8080 \
  -e SSSO_SIGNING_KEY_PATH=/etc/sso/keys/private.pem \
  -e SSSO_CONFIG_ENCRYPTION_KEY=$(openssl rand -hex 32) \
  -v $(pwd)/keys:/etc/sso/keys:ro \
  ghcr.io/pilab-dev/shadow-sso-backend:v1
```

## Volume Mounts

| Host Path | Container Path | Purpose |
|-----------|---------------|---------|
| `./keys` | `/etc/sso/keys` | RSA signing keys |
| `./firebase-creds` | `/etc/sso/firebase` | Firebase credentials (optional) |

## Environment Variables

See the [Configuration Reference](/configuration/reference) for all available options.

### Minimal Required Variables

```bash
SSSO_MONGO_URI=mongodb://mongodb:27017
SSSO_SIGNING_KEY_PATH=/etc/sso/keys/private.pem
SSSO_CONFIG_ENCRYPTION_KEY=<32-byte-hex-string>
```

### Recommended Variables

```bash
SSSO_ISSUER_URL=https://sso.example.com
SSSO_LOG_LEVEL=info
SSSO_JSON_LOG=true
SSSO_INITIAL_ADMIN_ENABLED=true
SSSO_INITIAL_ADMIN_EMAIL=admin@example.com
SSSO_INITIAL_ADMIN_PASSWORD=<strong-password>
```

## Health Checks

The Docker image includes a built-in health check:

```bash
# Check container health
docker inspect --format='{{.State.Health.Status}}' ssso

# View health check logs
docker inspect --format='{{json .State.Health}}' ssso | jq
```

### Health Endpoints

| Endpoint | Port | Purpose |
|----------|------|---------|
| `/healthz` | 5000 | Liveness probe |
| `/readyz` | 5000 | Readiness probe |
| `/metrics` | 5000 | Prometheus metrics |

## Building Custom Images

Build from source:

```bash
docker build -t shadow-sso:custom .
```

### Multi-stage Build

The Dockerfile uses a multi-stage build:

```dockerfile
# Stage 1: Build
FROM golang:1.25-alpine AS builder
# ... build steps ...

# Stage 2: Runtime
FROM alpine:3.21
# ... minimal runtime image ...
```

This produces a small final image (~50MB) with only the compiled binary.

## Troubleshooting

### Container Won't Start

```bash
# View logs
docker logs ssso

# Check if MongoDB is reachable
docker exec ssso nc -zv mongodb 27017

# Verify signing key exists
docker exec ssso ls -la /etc/sso/keys/
```

### Permission Denied

The container runs as non-root user `appuser` (UID 1001). Ensure mounted volumes have correct permissions:

```bash
# Fix key file permissions
chmod 644 ./keys/private.pem
chown 1001:1001 ./keys/private.pem
```

## Next Steps

- [Docker Compose](/deployment/docker-compose) - Multi-container orchestration
- [Kubernetes Deployment](/deployment/kubernetes) - Production-grade deployment
- [Configuration Reference](/configuration/reference) - All configuration options
