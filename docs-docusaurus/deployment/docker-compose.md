---
id: docker-compose
title: Docker Compose
sidebar_label: Docker Compose
---

# Docker Compose Deployment

Deploy Shadow SSO with Docker Compose for easy multi-container orchestration.

## Overview

Docker Compose is ideal for:
- Development environments
- Small-scale deployments
- Quick prototyping
- Local testing

## Prerequisites

- Docker Compose v2.0+
- At least 1GB RAM available

## Basic Setup

### 1. Create Project Directory

```bash
mkdir shadow-sso-deploy
cd shadow-sso-deploy
```

### 2. Generate Signing Key

```bash
mkdir -p docker/keys
openssl genrsa -out docker/keys/private.pem 2048
```

### 3. Create Environment File

```bash
cat > .env << 'EOF'
# Core Configuration
SSSO_HTTP_ADDR=0.0.0.0:8080
SSSO_MGMT_HTTP_ADDR=:5000
SSSO_LOG_LEVEL=debug
SSSO_JSON_LOG=false
SSSO_ISSUER_URL=http://localhost:8080

# Database
SSSO_MONGO_URI=mongodb://mongo:27017
SSSO_MONGO_DB_NAME=shadow_sso_dev
SSSO_STORAGE_BACKEND=mongodb

# Security
SSSO_SIGNING_KEY_PATH=/etc/sso/keys/private.pem
SSSO_CONFIG_ENCRYPTION_KEY=change-this-to-a-32-byte-hex-string-000000

# Initial Admin
SSSO_INITIAL_ADMIN_ENABLED=true
SSSO_INITIAL_ADMIN_EMAIL=admin@localhost
SSSO_INITIAL_ADMIN_PASSWORD=admin
SSSO_INITIAL_ADMIN_FIRST_NAME=Admin
SSSO_INITIAL_ADMIN_LAST_NAME=User
EOF
```

:::warning
Change `SSSO_CONFIG_ENCRYPTION_KEY` to a random 32-byte hex string for production. Generate one with:
```bash
openssl rand -hex 32
```
:::

### 4. Create Docker Compose File

```yaml
# docker-compose.yml
services:
  mongo:
    image: mongo:7
    ports:
      - "27017:27017"
    volumes:
      - mongo_data:/data/db
    healthcheck:
      test: echo 'db.runCommand("ping").ok' | mongosh --quiet
      interval: 10s
      timeout: 5s
      retries: 5
    restart: unless-stopped

  ssso:
    image: ghcr.io/pilab-dev/shadow-sso-backend:v1
    depends_on:
      mongo:
        condition: service_healthy
    ports:
      - "8080:8080"
      - "5000:5000"
    env_file:
      - .env
    volumes:
      - ./docker/keys:/etc/sso/keys:ro
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:5000/healthz"]
      interval: 15s
      timeout: 3s
      start_period: 30s
      retries: 3

volumes:
  mongo_data:
```

### 5. Start Services

```bash
docker compose up -d
```

### 6. Verify Deployment

```bash
# Check service status
docker compose ps

# Check logs
docker compose logs -f ssso

# Test health endpoint
curl http://localhost:5000/healthz
```

## Complete Example with All Features

```yaml
# docker-compose.full.yml
services:
  mongo:
    image: mongo:7
    ports:
      - "27017:27017"
    volumes:
      - mongo_data:/data/db
    healthcheck:
      test: echo 'db.runCommand("ping").ok' | mongosh --quiet
      interval: 10s
      timeout: 5s
      retries: 5
    restart: unless-stopped

  # Optional: Distributed Token Store
  ssso-dts:
    image: ghcr.io/pilab-dev/shadow-sso-dts:latest
    ports:
      - "50051:50051"
    volumes:
      - dts_data:/data
    environment:
      - DTS_GRPC_SERVER_ADDRESS=0.0.0.0:50051
      - DTS_BBOLTDB_PATH=/data/dts.db
      - DTS_DEFAULT_TTL_SECONDS=3600
    restart: unless-stopped

  ssso:
    image: ghcr.io/pilab-dev/shadow-sso-backend:v1
    depends_on:
      mongo:
        condition: service_healthy
    ports:
      - "8080:8080"
      - "5000:5000"
    env_file:
      - .env
    environment:
      # Override to use DTS backend
      - SSSO_STORAGE_BACKEND=dts
      - SSSO_DTS_CLIENT_ADDRESS=ssso-dts:50051
    volumes:
      - ./docker/keys:/etc/sso/keys:ro
      - ./docker/firebase:/etc/sso/firebase:ro  # Optional
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:5000/healthz"]
      interval: 15s
      timeout: 3s
      start_period: 30s
      retries: 3

volumes:
  mongo_data:
  dts_data:
```

## Environment Variables Reference

### Core Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `SSSO_HTTP_ADDR` | `0.0.0.0:8080` | HTTP server address |
| `SSSO_MGMT_HTTP_ADDR` | `:5000` | Management HTTP address |
| `SSSO_LOG_LEVEL` | `info` | Log level |
| `SSSO_JSON_LOG` | `false` | Enable JSON logging |
| `SSSO_ISSUER_URL` | `http://localhost:8080` | OIDC issuer URL |

### Database Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `SSSO_MONGO_URI` | `mongodb://localhost:27017` | MongoDB connection URI |
| `SSSO_MONGO_DB_NAME` | `shadow_sso_db` | Database name |
| `SSSO_STORAGE_BACKEND` | `mongodb` | `mongodb` or `dts` |

### DTS Configuration (when using DTS backend)

| Variable | Default | Description |
|----------|---------|-------------|
| `SSSO_DTS_CLIENT_ADDRESS` | `ssso-dts:50051` | DTS gRPC address |
| `SSSO_DTS_TIMEOUT` | `5s` | Connection timeout |

### Security Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `SSSO_SIGNING_KEY_PATH` | (required) | RSA private key path |
| `SSSO_CONFIG_ENCRYPTION_KEY` | (auto) | 32-byte encryption key |
| `SSSO_KEY_ROTATION_INTERVAL` | `24h` | Key rotation interval |

### Notification Services (Optional)

| Variable | Description |
|----------|-------------|
| `SSSO_RESEND_API_KEY` | Resend API key for email |
| `SSSO_FROM_EMAIL` | Sender email address |
| `SSSO_TWILIO_ACCOUNT_SID` | Twilio account SID |
| `SSSO_TWILIO_AUTH_TOKEN` | Twilio auth token |
| `SSSO_TWILIO_PHONE_NUMBER` | Twilio phone number |
| `SSSO_FIREBASE_PROJECT_ID` | Firebase project ID |
| `SSSO_FIREBASE_CREDENTIALS_PATH` | Firebase credentials path |

## Operations

### Start Services

```bash
docker compose up -d
```

### Stop Services

```bash
docker compose down
```

### Stop and Remove Data

```bash
docker compose down -v
```

### View Logs

```bash
# All services
docker compose logs -f

# Specific service
docker compose logs -f ssso

# Last 100 lines
docker compose logs --tail=100 ssso
```

### Restart Services

```bash
docker compose restart
```

### Update Images

```bash
docker compose pull
docker compose up -d
```

## Backup and Restore

### Backup MongoDB

```bash
docker compose exec mongo mongodump --archive=/backup/mongo-$(date +%Y%m%d).gz --gzip
docker cp $(docker compose ps -q mongo):/backup/ ./backups/
```

### Restore MongoDB

```bash
docker cp ./backups/mongo-20240101.gz $(docker compose ps -q mongo):/backup/
docker compose exec mongo mongorestore --archive=/backup/mongo-20240101.gz --gzip
```

## Production Considerations

:::warning
Docker Compose is not recommended for production. Use [Kubernetes with Helm](/deployment/kubernetes) instead.
:::

For production-like setups:
- Use external MongoDB (not containerized)
- Set `SSSO_LOG_LEVEL=info` and `SSSO_JSON_LOG=true`
- Use strong passwords and encryption keys
- Enable TLS/HTTPS via reverse proxy
- Set up monitoring and alerting

## Next Steps

- [Kubernetes Deployment](/deployment/kubernetes) - Production-grade deployment
- [Configuration Reference](/configuration/reference) - All options
- [Monitoring](/operations/monitoring) - Set up observability
