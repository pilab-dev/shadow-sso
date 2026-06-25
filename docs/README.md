# Shadow SSO Documentation Index

This file provides an overview of all documentation available for Shadow SSO.

## Getting Started

| Document | Description |
|----------|------------|
| [README.md](../README.md) | Main project README with features, installation, and quick start |
| [docs/api.md](./api.md) | gRPC API services documentation |

## Core Features

| Document | Description |
|----------|------------|
| [docs/federation.md](./federation.md) | Identity provider federation (Google, Facebook, Apple, GitHub) |
| [docs/service_accounts_usage.md](./service_accounts_usage.md) | Service account keys and JWT authentication |
| [docs/user_attributes.md](./user_attributes.md) | Custom user attributes and token claim mappers |

## Security & Keys

| Document | Description |
|----------|------------|
| [docs/client_keys.md](./client_keys.md) | OAuth client JWKS and key generation |
| [docs/realm_keys.md](./realm_keys.md) | Realm signing keys for JWT tokens |
| [docs/protocol_mappers.md](./protocol_mappers.md) | Token protocol mappers for claims |

## API Reference

| Document | Description |
|----------|------------|
| [docs/graphql.md](./graphql.md) | GraphQL API for administration |
| [docs/cli.md](./cli.md) | ssoctl CLI tool usage |

## Configuration & Setup

| Document | Description |
|----------|------------|
| [docs/ldap_setup.md](./ldap_setup.md) | LDAP/Active Directory integration |
| [docs/ldap-user-repository-plan.md](./ldap-user-repository-plan.md) | LDAP user repository design |

## Quick Links

- **Main README**: [README.md](../README.md)
- **GraphQL Playground**: `/graphql/playground` (when server running)
- **Metrics**: Prometheus metrics at `/metrics` endpoint