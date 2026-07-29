---
id: index
title: Shadow SSO Documentation
sidebar_label: Welcome
slug: /
---

# Shadow SSO Documentation

Welcome to the official Shadow SSO documentation. Shadow SSO is a production-grade, Go-powered OAuth 2.0 and OpenID Connect identity provider designed for modern applications.

## What is Shadow SSO?

Shadow SSO (3SO) is a headless Single Sign-On solution that provides:

- **Full OAuth 2.0 & OpenID Connect compliance** (RFC 6749, RFC 7636, RFC 7662, RFC 7009)
- **Multi-factor authentication** (TOTP, Email, Push Notifications, SMS)
- **Distributed architecture** with optional Distributed Token Store (DTS)
- **Enterprise integrations** (LDAP/AD, Identity Provider Federation)
- **Machine identities** via Service Accounts with JWT authentication
- **GraphQL API** for administrative operations
- **CLI tool** (`ssoctl`) for management automation

## Architecture Overview

```
                    +-------------------+
                    |   Client Apps     |
                    |   (Web, Mobile)   |
                    +--------+----------+
                             |
                    OAuth2/OIDC Flow
                             |
                    +--------v----------+
                    |   Shadow SSO      |
                    |   (ssso)          |
                    +--------+----------+
                             |
              +--------------+--------------+
              |              |              |
     +--------v---+  +------v-----+  +-----v-------+
     |  MongoDB   |  |   DTS      |  |  External   |
     |  (Users,   |  |  (Tokens,  |  |  Services   |
     |   Clients) |  |   Sessions)|  |  (Email,SMS)|
     +------------+  +------------+  +-------------+
```

## Key Components

| Component | Description |
|-----------|-------------|
| **ssso** | Main SSO server application |
| **ssoctl** | Command-line interface for management |
| **ssso-dts** | Distributed Token Store (optional) |
| **GraphQL API** | Administrative API endpoint |
| **gRPC API** | High-performance service API |

## Quick Navigation

### Getting Started
- [Installation Guide](/getting-started/installation)
- [Quick Start](/getting-started/quickstart)
- [Configuration Basics](/getting-started/configuration)

### Deployment
- [Docker Deployment](/deployment/docker)
- [Docker Compose](/deployment/docker-compose)
- [Kubernetes with Helm](/deployment/kubernetes)

### Operations
- [Configuration Reference](/configuration/reference)
- [Maintenance & Backup](/operations/maintenance)
- [Monitoring & Metrics](/operations/monitoring)
- [Troubleshooting](/troubleshooting/common-issues)

### Features
- [Federation & IdP](/features/federation)
- [LDAP/Active Directory](/features/ldap)
- [Service Accounts](/features/service-accounts)
- [Multi-Factor Authentication](/features/mfa)

### API Reference
- [gRPC API](/api-reference/grpc)
- [GraphQL API](/api-reference/graphql)
- [CLI Reference](/api-reference/cli)

## Support & Community

- **GitHub Issues**: [Report bugs and request features](https://github.com/pilab-dev/shadow-sso/issues)
- **Security**: Report vulnerabilities to [gyula@pilab.hu](mailto:gyula@pilab.hu)
- **License**: MIT License

## Version Information

| Version | Status | Go Version |
|---------|--------|------------|
| v1.x | Current | Go 1.25+ |
