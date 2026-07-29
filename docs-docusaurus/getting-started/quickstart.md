---
id: quickstart
title: Quick Start
sidebar_label: Quick Start
---

# Quick Start Guide

Get Shadow SSO running in under 5 minutes.

## Prerequisites

- Docker and Docker Compose installed
- At least 512MB RAM available

## Step 1: Start MongoDB

Start a MongoDB instance:

```bash
docker run -d \
  --name mongodb \
  -p 27017:27017 \
  mongo:7
```

Wait for MongoDB to be ready:

```bash
docker exec mongodb mongosh --eval 'db.runCommand("ping").ok'
```

## Step 2: Generate Signing Key

Generate an RSA private key for JWT signing:

```bash
mkdir -p ./keys
openssl genrsa -out ./keys/private.pem 2048
```

## Step 3: Start Shadow SSO

Run the SSO server with Docker:

```bash
docker run -d \
  --name ssso \
  -p 8080:8080 \
  -p 5000:5000 \
  -e SSSO_MONGO_URI=mongodb://host.docker.internal:27017 \
  -e SSSO_ISSUER_URL=http://localhost:8080 \
  -e SSSO_SIGNING_KEY_PATH=/etc/sso/keys/private.pem \
  -e SSSO_INITIAL_ADMIN_ENABLED=true \
  -e SSSO_INITIAL_ADMIN_EMAIL=admin@example.com \
  -e SSSO_INITIAL_ADMIN_PASSWORD=changeme123 \
  -v $(pwd)/keys:/etc/sso/keys:ro \
  ghcr.io/pilab-dev/shadow-sso-backend:v1
```

## Step 4: Verify the Server

Check the health endpoint:

```bash
curl http://localhost:5000/healthz
# Expected: {"status":"ok"}
```

Check the OIDC discovery endpoint:

```bash
curl http://localhost:8080/.well-known/openid-configuration
```

## Step 5: Configure the CLI

Install and configure `ssoctl`:

```bash
# Install ssoctl
go install github.com/pilab-dev/shadow-sso/apps/ssoctl@latest

# Set up context
ssoctl config set-context local --server http://localhost:8080
ssoctl config use-context local

# Login as admin
ssoctl auth login
# Email: admin@example.com
# Password: changeme123
```

## Step 6: Create Your First Client

Register an OAuth2 client:

```bash
ssoctl client register \
  --name "My App" \
  --type confidential \
  --redirect-uris http://localhost:3000/callback \
  --grant-types authorization_code,refresh_token
```

Save the returned `client_id` and `client_secret`.

## Step 7: Create a User

Register a test user:

```bash
ssoctl user register \
  --email user@example.com \
  --password "SecurePass123!" \
  --first-name Test \
  --last-name User
```

## What's Next?

- [Full Configuration Guide](/configuration/reference)
- [Docker Compose Deployment](/deployment/docker-compose)
- [Enable Multi-Factor Authentication](/features/mfa)
- [Set Up Federation](/features/federation)

## Quick Reference

| Endpoint | URL |
|----------|-----|
| Health Check | `http://localhost:5000/healthz` |
| OIDC Discovery | `http://localhost:8080/.well-known/openid-configuration` |
| Authorization | `http://localhost:8080/oauth2/authorize` |
| Token | `http://localhost:8080/oauth2/token` |
| JWKS | `http://localhost:8080/.well-known/jwks.json` |
| GraphQL | `http://localhost:8080/graphql` |
| GraphQL Playground | `http://localhost:8080/graphql/playground` |
