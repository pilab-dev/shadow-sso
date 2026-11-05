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
| `oidc-usermodel-attribute-mapper` | Map a user attribute to a claim | `claim.name`, `user.attribute`, `multivalued` |
| `oidc-usermodel-realm-role-mapper` | Map the user's realm roles | `claim.name`, `multivalued` |
| `oidc-usermodel-client-role-mapper` | Map the user's client roles | `claim.name`, `multivalued` |
| `oidc-group-membership-mapper` | Map group membership | `claim.name`, `multivalued` |
| `oidc-hardcoded-claim-mapper` | Emit a constant claim | `claim.name`, `claim.value`, `multivalued` |

Other Keycloak mapper types (`oidc-usermodel-property-mapper`,
`oidc-audience-mapper`, `oidc-full-name-mapper`, …) are not implemented yet and
are skipped silently. Mapper types are matched case-insensitively on their
name, and non-`openid-connect` mappers are ignored.

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

Applied to all clients in the realm. Stored without a `client_id` (an explicit
`null` or empty string is treated the same way). When a client defines a mapper
with the same claim name, the client-specific mapper wins because it is applied
after the realm-wide one.

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

## ConnectRPC API

The canonical admin API is `sso.v1.ProtocolMapperService` (Connect, gRPC and
gRPC-Web), backed by the same repository as the GraphQL API:

| RPC | Purpose |
|-----|---------|
| `CreateProtocolMapper` | Create a client-specific or realm-wide mapper (`client_id` unset = realm-wide) |
| `GetProtocolMapper` | Read one mapper |
| `ListProtocolMappers` | List all; `client_id` returns the effective set (own + realm-wide); `realm_only` returns only realm-wide |
| `UpdateProtocolMapper` | Partial update; `client_id: ""` moves to realm level, `clear_config` drops the config map |
| `DeleteProtocolMapper` | Delete one mapper |

CLI equivalents:

```bash
ssoctl protocol-mapper create --name email --mapper oidc-usermodel-attribute-mapper \
  --mapper-config claim.name=email --mapper-config user.attribute=email --client-id my-client
ssoctl protocol-mapper list --client-id my-client
ssoctl protocol-mapper list --realm-only
ssoctl protocol-mapper update <ID> --client-id ""
ssoctl protocol-mapper delete <ID>
```

## GraphQL API

### Queries

```graphql
# Get every mapper (realm-wide and client-specific)
tokenMappers: [ProtocolMapper!]!

# Get the mappers that apply to a client: its own + realm-wide ones
clientTokenMappers(clientId: String!): [ProtocolMapper!]!

# Get only the realm-wide mappers
realmTokenMappers: [ProtocolMapper!]!
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
    clientId: ID  # Optional - omitted/null for realm-level
}

input UpdateProtocolMapperInput {
    name: String
    protocol: String
    protocolMapper: String
    config: Map
    clientId: ID  # Set to "" to move the mapper to realm level
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