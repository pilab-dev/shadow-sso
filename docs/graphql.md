# GraphQL API

This document describes the GraphQL API in shadow-sso for administrative operations.

## Overview

Shadow SSO provides a GraphQL API for managing users, clients, roles, groups, identity providers, authentication flows, and realm settings. This is primarily an administrative API.

## Endpoint

```
POST /graphql
```

### Development Playground

```
GET /graphql/playground
```

## Authentication

### Option 1: Bearer Token

Include a JWT token in the Authorization header:

```bash
curl -X POST http://localhost:8080/graphql \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"query":"{ users { edges { node { id email } } } }"}'
```

### Option 2: GraphQL Header

Pass token in GraphQL-specific header:

```bash
curl -X POST http://localhost:8080/graphql \
  -H "SSSO-Token: <token>" \
  -H "Content-Type: application/json" \
  -d '{"query":"{ realm { id realm } }"}'
```

## Root Query

### Users

```graphql
type Query {
    # List users with pagination
    users(filter: UserFilter, first: Int, after: Int): UserConnection!
    
    # Get single user
    user(id: ID!): User
}
```

### Clients

```graphql
# List clients
clients(filter: ClientFilter, first: Int, after: Int): ClientConnection!

# Get client by internal ID
client(id: ID!): Client

# Get client by client_id
clientByClientId(clientId: String!): Client
```

### Roles

```graphql
# All realm roles
roles: [Role!]!

# Single role
role(id: ID!): Role

# Realm roles only
realmRoles: [Role!]!

# Client-specific roles
clientRoles(clientId: String!): [Role!]!
```

### Groups

```graphql
groups: [Group!]!
group(id: ID!): Group
groupMembers(groupId: ID!, first: Int, after: Int): UserConnection!
```

### Sessions

```graphql
sessions(userId: ID, first: Int, after: Int): SessionConnection!
session(id: ID!): Session
userSessions(userId: ID!): [Session!]!
clientUserSessions(userId: ID!, clientId: String!): [Session!]!
```

### Identity Providers

```graphql
identityProviders: [IdentityProvider!]!
identityProvider(id: ID!): IdentityProvider
```

### Realm

```graphql
realm: RealmSettings!
```

### Token Introspection (Public)

```graphql
introspectToken(token: String!): TokenIntrospection!
```

### Authentication Flows

```graphql
authenticationFlows: [AuthenticationFlow!]!
authenticationExecutions(flowId: ID!): [AuthenticationExecution!]!
```

### Token Mappers

```graphql
tokenMappers: [ProtocolMapper!]!
clientTokenMappers(clientId: String!): [ProtocolMapper!]!
```

### Role Mappings

```graphql
roleMappings(userId: ID!): RoleMapping!
clientRoleMappings(userId: ID!, clientId: String!): [Role!]!
userGroups(userId: ID!): [Group!]!
```

### User Attributes (Enterprise)

```graphql
userAttributes(userId: ID!): [UserAttribute!]!
userAttributeMappers: [UserAttributeMapper!]!
clientUserAttributeMappers(clientId: String!): [UserAttributeMapper!]!
```

### Keys

```graphql
realmKeys: [RealmKey!]!
```

## Root Mutation

### User Management

```graphql
type Mutation {
    createUser(input: CreateUserInput!): User!
    updateUser(id: ID!, input: UpdateUserInput!): User!
    deleteUser(id: ID!): Boolean!
    
    sendVerificationEmail(userId: ID!): Boolean!
    sendPasswordResetEmail(userId: ID!): Boolean!
    resetPassword(userId: ID!, newPassword: String!): Boolean!
    executeActions(userId: ID!, actions: [String!]!): Boolean!
    
    setUserPassword(userId: ID!, password: String!, temporary: Boolean!): Boolean!
    deleteUserCredentials(userId: ID!, credentialId: String!): Boolean!
    resetUserTwoFactor(userId: ID!): Boolean!
}
```

### Client Management

```graphql
createClient(input: CreateClientInput!): Client!
updateClient(id: ID!, input: UpdateClientInput!): Client!
deleteClient(id: ID!): Boolean!

generateClientSecret(clientId: ID!): String!
generateClientKeys(clientId: ID!, keyType: String, keyBits: Int): JSON!
```

### Role Management

```graphql
createRole(input: CreateRoleInput!): Role!
updateRole(id: ID!, input: UpdateRoleInput!): Role!
deleteRole(id: ID!): Boolean!

addRealmRoleToUser(userId: ID!, roleId: ID!): Boolean!
removeRealmRoleFromUser(userId: ID!, roleId: ID!): Boolean!
addClientRoleToUser(userId: ID!, clientId: String!, roleId: ID!): Boolean!
removeClientRoleFromUser(userId: ID!, clientId: String!, roleId: ID!): Boolean!

addRealmRoleToGroup(groupId: ID!, roleId: ID!): Boolean!
removeRealmRoleFromGroup(groupId: ID!, roleId: ID!): Boolean!
addClientRoleToGroup(groupId: ID!, clientId: String!, roleId: ID!): Boolean!
removeClientRoleFromGroup(groupId: ID!, clientId: String!, roleId: ID!): Boolean!

createCompositeRole(input: CreateCompositeRoleInput!): Role!
```

### Group Management

```graphql
createGroup(input: CreateGroupInput!): Group!
updateGroup(id: ID!, input: UpdateGroupInput!): Group!
deleteGroup(id: ID!): Boolean!

addUserToGroup(userId: ID!, groupId: ID!): Boolean!
removeUserFromGroup(userId: ID!, groupId: ID!): Boolean!
```

### Identity Provider Management

```graphql
createIdentityProvider(input: CreateIdentityProviderInput!): IdentityProvider!
updateIdentityProvider(id: ID!, input: UpdateIdentityProviderInput!): IdentityProvider!
deleteIdentityProvider(id: ID!): Boolean!
```

### Session Management

```graphql
revokeSession(sessionId: ID!): Boolean!
revokeAllSessions(userId: ID!): Boolean!
logoutUser(userId: ID!): Boolean!
```

### Realm Settings

```graphql
updateRealm(input: UpdateRealmInput!): RealmSettings!
updateRealmKeys(input: UpdateRealmKeysInput!): [RealmKey!]!
```

### Protocol Mappers

```graphql
createProtocolMapper(input: CreateProtocolMapperInput!): ProtocolMapper!
updateProtocolMapper(id: ID!, input: UpdateProtocolMapperInput!): ProtocolMapper!
deleteProtocolMapper(id: ID!): Boolean!
```

### User Attributes (Enterprise)

```graphql
createUserAttribute(input: CreateUserAttributeInput!): UserAttribute!
updateUserAttribute(id: ID!, input: UpdateUserAttributeInput!): UserAttribute!
deleteUserAttribute(id: ID!): Boolean!
deleteUserAttributesByUserId(userId: ID!): Boolean!

createUserAttributeMapper(input: CreateUserAttributeMapperInput!): UserAttributeMapper!
updateUserAttributeMapper(id: ID!, input: UpdateUserAttributeMapperInput!): UserAttributeMapper!
deleteUserAttributeMapper(id: ID!): Boolean!
```

### Authentication Flows

```graphql
createAuthenticationFlow(input: CreateAuthenticationFlowInput!): AuthenticationFlow!
updateAuthenticationFlow(id: ID!, input: UpdateAuthenticationFlowInput!): AuthenticationFlow!
deleteAuthenticationFlow(id: ID!): Boolean!
updateAuthenticationExecutions(flowId: ID!, executions: [AuthenticationExecutionInput!]!): Boolean!
```

### Client Scopes

```graphql
createClientScope(input: CreateClientScopeInput!): ClientScope!
deleteClientScope(id: ID!): Boolean!
```

## Pagination

Connections follow the Relay cursor specification:

```graphql
type UserConnection {
    edges: [UserEdge!]!
    totalCount: Int!
    pageInfo: PageInfo!
}

type UserEdge {
    node: User!
    cursor: String!
}

type PageInfo {
    hasNextPage: Boolean!
    hasPreviousPage: Boolean!
    startCursor: String
    endCursor: String
}
```

## Example Queries

### Paginated Users

```graphql
query {
    users(first: 10, after: "cursor-from-previous") {
        edges {
            node {
                id
                email
                firstName
                lastName
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

### Filtered Clients

```graphql
query {
    clients(filter: { enabled: true, search: "app-" }) {
        edges {
            node {
                id
                clientId
                clientName
                enabled
            }
        }
    }
}
```

### User with Sessions

```graphql
query {
    user(id: "user-123") {
        id
        email
        sessions {
            id
            ipAddress
            createdTime
            expires
        }
    }
}
```

## Example Mutations

### Create User

```graphql
mutation {
    createUser(input: {
        username: "john.doe"
        email: "john@example.com"
        firstName: "John"
        lastName: "Doe"
        credentials: [{
            type: "password"
            value: "securePassword123"
            temporary: false
        }]
    }) {
        id
        email
        createdTimestamp
    }
}
```

### Create OAuth Client

```graphql
mutation {
    createClient(input: {
        clientId: "my-web-app"
        clientName: "My Web Application"
        enabled: true
        redirectUris: ["https://myapp.example.com/callback"]
        allowedGrantTypes: ["authorization_code", "refresh_token"]
        standardFlowEnabled: true
    }) {
        id
        clientId
        clientSecret
    }
}
```

### Update Realm Settings

```graphql
mutation {
    updateRealm(input: {
        displayName: "My Organization SSO"
        registrationAllowed: false
        resetPasswordAllowed: true
        passwordPolicy: {
            length: 12
            lowerCase: 1
            upperCase: 1
            digits: 1
            specialChars: 1
        }
    }) {
        id
        displayName
    }
}
```

## Scalar Types

| Scalar | Description |
|--------|-------------|
| `Time` | ISO 8601 timestamp |
| `Map` | JSON object |
| `JSON` | Any JSON value |

## Type Reference

### User

```graphql
type User {
    id: ID!
    username: String!
    email: String!
    firstName: String
    lastName: String
    enabled: Boolean!
    emailVerified: Boolean!
    createdTimestamp: Time!
    lastAccess: Time
    status: UserStatus!
    groups: [Group!]!
    federatedIdentities: [FederatedIdentity!]!
    attributes: Map
    totp: Boolean!
}
```

### Client

```graphql
type Client {
    id: ID!
    clientId: String!
    clientName: String!
    description: String
    enabled: Boolean!
    createdTimestamp: Time!
    redirectUris: [String!]!
    webOrigins: [String!]!
    allowedGrantTypes: [String!]!
    standardFlowEnabled: Boolean!
    implicitFlowEnabled: Boolean!
    directAccessGrantsEnabled: Boolean!
    publicClient: Boolean!
    jwks: JSON
    jwksUri: String
    scope: [ClientScope!]
    roles: [Role!]!
    attributes: Map
}
```

### Session

```graphql
type Session {
    id: ID!
    userId: String!
    username: String
    ipAddress: String!
    userAgent: String
    createdTime: Time!
    lastAccessedTime: Time!
    expires: Time!
    state: String
    clientId: String
    clientName: String
}
```

## Related Documentation

- [Client Keys](./client_keys.md) - OAuth client JWKS
- [Protocol Mappers](./protocol_mappers.md) - Token claim mapping  
- [User Attributes](./user_attributes.md) - Custom user attributes
- [Realm Keys](./realm_keys.md) - Realm signing keys