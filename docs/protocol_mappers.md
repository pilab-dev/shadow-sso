# Token Protocol Mappers

This document describes the protocol mappers in shadow-sso for token claim mapping.

## Overview

Protocol mappers define how user attributes, roles, and other data are mapped to OAuth/OIDC tokens. They transform user data into token claims during token generation.

## Data Model

### ProtocolMapper

Represents a Keycloak-style protocol mapper.

| Field | Type | Description |
|-------|------|-------------|
| id | string | Unique identifier |
| name | string | Mapper name |
| protocol | string | Protocol (openid-connect, saml) |
| protocolMapper | string | Mapper type |
| config | map[string]any | Mapper configuration |
| clientId | string | Optional associated client |

```go
type ProtocolMapper struct {
    ID              string         `bson:"_id,omitempty" json:"id"`
    Name            string         `bson:"name" json:"name"`
    Protocol       string         `bson:"protocol" json:"protocol"`
    ProtocolMapper string         `bson:"protocol_mapper" json:"protocolMapper"`
    Config        map[string]any  `bson:"config,omitempty" json:"config,omitempty"`
    ClientID       string         `bson:"client_id,omitempty" json:"clientId,omitempty"`
}
```

## Mapper Types

### Built-in Mapper Types

| Mapper Type | Description | Config Options |
|-----------|-------------|--------------|
| `oidc-usermodel-attributemapper` | Map user attributes to claims | `claim.name`, `user.attribute`, `json.type` |
| `oidc-usermodel-protocol-mapper` | Protocol-level user mapping | `claim.name`, `access.token.claim` |
| `oidc-group-membership-mapper` | Map group membership | `claim.name`, `groups` |
| `oidc-role-list-mapper` | Map user's roles | `claim.name`, `full.path` |
| `saml-group-membership-mapper` | SAML group mapping | `claim.name` |

### Config Examples

#### User Attribute Mapper

```json
{
    "name": "email_mapper",
    "protocol": "openid-connect", 
    "protocol_mapper": "oidc-usermodel-attributemapper",
    "config": {
        "claim.name": "email",
        "user.attribute": "email",
        "json.type": "string"
    }
}
```

#### Group Mapper

```json
{
    "name": "groups_mapper",
    "protocol": "openid-connect",
    "protocol_mapper": "oidc-group-membership-mapper", 
    "config": {
        "claim.name": "groups",
        "full.path": false
    }
}
```

## Realm-Level vs Client-Level Mappers

### Realm Mappers

Applied to all clients in the realm. Stored with `client_id: null`.

```graphql
# Create realm-level mapper
mutation {
    createProtocolMapper(input: {
        name: "realm_email_mapper",
        protocol: "openid-connect",
        protocolMapper: "oidc-usermodel-attributemapper",
        config: {
            "claim.name": "email", 
            "user.attribute": "email"
        },
        # No clientId = realm-level
    }) {
        id, name
    }
}
```

### Client Mappers

Applied only to specific clients.

```graphql
# Create client-specific mapper
mutation {
    createProtocolMapper(input: {
        name: "custom_client_mapper",
        protocol: "openid-connect",
        protocolMapper: "oidc-usermodel-attributemapper",
        config: {
            "claim.name": "department",
            "user.attribute": "custom_dept"
        },
        clientId: "client-123"
    }) {
        id, name, clientId
    }
}
```

## GraphQL API

### Queries

```graphql
# Get all realm-level token mappers
tokenMappers: [ProtocolMapper!]!

# Get token mappers for specific client
clientTokenMappers(clientId: String!): [ProtocolMapper!]!
```

### Mutations

```graphql
# Create mapper
createProtocolMapper(input: CreateProtocolMapperInput!): ProtocolMapper!

# Update mapper  
updateProtocolMapper(id: ID!, input: UpdateProtocolMapperInput!): ProtocolMapper!

# Delete mapper
deleteProtocolMapper(id: ID!): Boolean!
```

### Input Types

```graphql
input CreateProtocolMapperInput {
    name: String!
    protocol: String!
    protocolMapper: String!
    config: Map
    clientId: ID  # Optional - null for realm-level
}

input UpdateProtocolMapperInput {
    name: String
    protocol: String
    protocolMapper: String  
    config: Map
}
```

## Usage Examples

### List All Mappers

```graphql
query {
    tokenMappers {
        id
        name
        protocol
        protocolMapper
        clientId
    }
}
```

### List Client Mappers

```graphql
query {
    clientTokenMappers(clientId: "my-client") {
        id
        name
        config
    }
}
```

### Create User Attribute Mapper

```graphql
mutation {
    createProtocolMapper(input: {
        name: "email_claim_mapper",
        protocol: "openid-connect",
        protocolMapper: "oidc-usermodel-attributemapper",
        config: {
            "claim.name": "email_verified",
            "user.attribute": "is_email_verified",
            "json.type": "boolean"
        }
    }) {
        id
        name
    }
}
```

### Update Mapper Config

```graphql
mutation {
    updateProtocolMapper(id: "mapper-123", input: {
        config: {
            "claim.name": "updated_claim",
            "new.attribute": "new_value"
        }
    }) {
        id
        config
    }
}
```

## Token Generation Flow

When tokens are generated:

1. **Standard claims** are always added (iss, sub, aud, exp, iat, etc.)
2. **Scope-based claims** are added based on requested scopes
3. **Protocol mappers** are applied:
   - Fetch realm-level mappers
   - Fetch client-specific mappers  
   - Apply each mapper's transformation
   - Add resulting claims to token
4. **User attributes** (if user attributes enabled)

## MongoDB Collection

### protocol_mappers

```json
{
    "_id": "mapper-123",
    "name": "email_mapper",
    "protocol": "openid-connect", 
    "protocol_mapper": "oidc-usermodel-attributemapper",
    "config": {
        "claim.name": "email",
        "user.attribute": "email"
    },
    "client_id": null  // null = realm-level
}
```

## Related Documentation

- [Client Keys](./client_keys.md) - Client JWKS management
- [User Attributes](./user_attributes.md) - Custom user attributes