---
id: graphql
title: GraphQL API
sidebar_label: GraphQL API
---

# GraphQL API Reference

Shadow SSO provides a GraphQL API for administrative operations.

## Overview

| Property | Value |
|----------|-------|
| Endpoint | `POST /graphql` |
| Playground | `GET /graphql/playground` |
| Auth | JWT Bearer Token or API Key |
| Format | JSON |

## Authentication

### Bearer Token

```bash
curl -X POST http://localhost:8080/graphql \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"query": "{ users { id email } }"}'
```

### API Key

```bash
curl -X POST http://localhost:8080/graphql \
  -H "X-API-Key: <api-key>" \
  -H "Content-Type: application/json" \
  -d '{"query": "{ users { id email } }"}'
```

## Queries

### Users

```graphql
# List users
query {
  users(filter: { status: ACTIVE }) {
    id
    email
    firstName
    lastName
    status
    roles
    createdAt
  }
}

# Get single user
query {
  user(id: "user-123") {
    id
    email
    firstName
    lastName
    status
    roles
    attributes {
      name
      value
    }
    twoFactorEnabled
    federatedIdentities {
      provider
      subject
    }
  }
}
```

### Clients

```graphql
# List clients
query {
  clients {
    id
    name
    clientId
    clientType
    redirectUris
    grantTypes
    enabled
  }
}

# Get single client
query {
  client(id: "client-123") {
    id
    name
    clientId
    clientSecret
    clientType
    redirectUris
    grantTypes
    scopes
    enabled
    protocolMappers {
      id
      name
      protocolMapper
    }
  }
}
```

### Roles

```graphql
# List roles
query {
  roles {
    id
    name
    description
    composite
    clientRole
  }
}
```

### Groups

```graphql
# List groups
query {
  groups {
    id
    name
    path
    members {
      id
      email
    }
  }
}
```

### Sessions

```graphql
# List active sessions
query {
  sessions {
    id
    userId
    clientId
    ipAddress
    createdAt
    expiresAt
  }
}
```

### Identity Providers

```graphql
# List identity providers
query {
  identityProviders {
    id
    name
    type
    enabled
    oidcConfig {
      issuerUrl
      clientId
      scopes
    }
    ldapConfig {
      serverUrl
      userBaseDn
    }
  }
}
```

### Realm Settings

```graphql
# Get realm settings
query {
  realm {
    name
    displayName
    issuerUrl
    accessTokenTtl
    refreshTokenTtl
    loginTheme
    enabledGrantTypes
  }
}
```

### Token Introspection

```graphql
# Introspect a token
query {
  tokenIntrospect(token: "eyJhbGc...") {
    active
    scope
    clientId
    username
    tokenType
    exp
    iat
  }
}
```

## Mutations

### User Management

```graphql
# Create user
mutation {
  createUser(input: {
    email: "new@example.com"
    password: "SecurePass123!"
    firstName: "New"
    lastName: "User"
    roles: ["user"]
  }) {
    id
    email
  }
}

# Update user
mutation {
  updateUser(id: "user-123", input: {
    firstName: "Updated"
    roles: ["user", "admin"]
  }) {
    id
    email
    roles
  }
}

# Delete user
mutation {
  deleteUser(id: "user-123")
}

# Reset password
mutation {
  resetPassword(userId: "user-123", newPassword: "NewPass123!")
}
```

### Client Management

```graphql
# Create client
mutation {
  createClient(input: {
    name: "My App"
    clientType: "confidential"
    redirectUris: ["https://app.example.com/callback"]
    grantTypes: ["authorization_code", "refresh_token"]
    scopes: ["openid", "profile", "email"]
  }) {
    id
    clientId
    clientSecret
  }
}

# Update client
mutation {
  updateClient(id: "client-123", input: {
    name: "Updated App"
    redirectUris: ["https://new.example.com/callback"]
  }) {
    id
    name
  }
}

# Delete client
mutation {
  deleteClient(id: "client-123")
}
```

### Role Management

```graphql
# Create role
mutation {
  createRole(input: {
    name: "custom-role"
    description: "A custom role"
  }) {
    id
    name
  }
}

# Update role
mutation {
  updateRole(id: "role-123", input: {
    description: "Updated description"
  }) {
    id
    description
  }
}

# Delete role
mutation {
  deleteRole(id: "role-123")
}
```

### Group Management

```graphql
# Create group
mutation {
  createGroup(input: {
    name: "developers"
    parentId: null
  }) {
    id
    name
    path
  }
}

# Add user to group
mutation {
  addUserToGroup(userId: "user-123", groupId: "group-456")
}

# Remove user from group
mutation {
  removeUserFromGroup(userId: "user-123", groupId: "group-456")
}
```

### Identity Provider Management

```graphql
# Create OIDC identity provider
mutation {
  createIdentityProvider(input: {
    name: "google"
    type: "OIDC"
    enabled: true
    oidcConfig: {
      issuerUrl: "https://accounts.google.com"
      clientId: "your-client-id"
      clientSecret: "your-client-secret"
      scopes: ["openid", "profile", "email"]
    }
  }) {
    id
    name
  }
}

# Update identity provider
mutation {
  updateIdentityProvider(id: "idp-123", input: {
    enabled: false
  }) {
    id
    enabled
  }
}

# Delete identity provider
mutation {
  deleteIdentityProvider(id: "idp-123")
}
```

### Realm Settings

```graphql
# Update realm settings
mutation {
  updateRealmSettings(input: {
    displayName: "My Organization"
    accessTokenTtl: "30m"
    refreshTokenTtl: "24h"
  }) {
    displayName
    accessTokenTtl
  }
}
```

### Session Management

```graphql
# Revoke specific session
mutation {
  revokeSession(sessionId: "session-123")
}

# Revoke all sessions for a user
mutation {
  revokeAllSessions(userId: "user-123")
}
```

## Schema Types

### User

```graphql
type User {
  id: ID!
  email: String!
  firstName: String
  lastName: String
  status: UserStatus!
  roles: [String!]!
  attributes: [UserAttribute!]!
  twoFactorEnabled: Boolean!
  federatedIdentities: [FederatedIdentity!]!
  createdAt: Time!
  updatedAt: Time!
}

enum UserStatus {
  PENDING
  ACTIVE
  LOCKED
  DISABLED
}

type UserAttribute {
  name: String!
  value: String!
}

type FederatedIdentity {
  provider: String!
  subject: String!
  email: String
}
```

### Client

```graphql
type Client {
  id: ID!
  name: String!
  clientId: String!
  clientSecret: String
  clientType: ClientType!
  redirectUris: [String!]!
  grantTypes: [String!]!
  scopes: [String!]!
  enabled: Boolean!
  protocolMappers: [ProtocolMapper!]!
  createdAt: Time!
  updatedAt: Time!
}

enum ClientType {
  CONFIDENTIAL
  PUBLIC
}

type ProtocolMapper {
  id: ID!
  name: String!
  protocol: String!
  protocolMapper: String!
  config: JSON!
}
```

### Input Types

```graphql
input CreateUserInput {
  email: String!
  password: String!
  firstName: String
  lastName: String
  roles: [String!]
  attributes: [AttributeInput!]
}

input UpdateUserInput {
  email: String
  firstName: String
  lastName: String
  status: UserStatus
  roles: [String!]
  attributes: [AttributeInput!]
}

input CreateClientInput {
  name: String!
  clientType: ClientType!
  redirectUris: [String!]!
  grantTypes: [String!]!
  scopes: [String!]
}
```

## Error Handling

GraphQL errors are returned in the `errors` array:

```json
{
  "errors": [
    {
      "message": "User not found",
      "path": ["user"],
      "extensions": {
        "code": "NOT_FOUND"
      }
    }
  ]
}
```

## Pagination

List queries support pagination:

```graphql
query {
  users(first: 10, after: "cursor-xyz") {
    edges {
      node {
        id
        email
      }
      cursor
    }
    pageInfo {
      hasNextPage
      endCursor
    }
  }
}
```

## Playground

Access the interactive GraphQL playground:

```
http://localhost:8080/graphql/playground
```

## Next Steps

- [gRPC API](/api-reference/grpc) - High-performance API
- [CLI Reference](/api-reference/cli) - Command-line interface
