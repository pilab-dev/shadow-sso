# User Attributes & Attribute Mappers

This document describes the user attributes and user attribute mappers feature in shadow-sso.

## Overview

User attributes allow storing custom key-value data associated with users. Attribute mappers define how these attributes are mapped to token claims during token generation.

## Data Model

### UserAttribute

Represents a custom attribute stored for a user.

| Field | Type | Description |
|-------|------|-------------|
| id | string | Unique identifier (auto-generated) |
| name | string | Attribute name (e.g., "department") |
| value | string | Attribute value (e.g., "engineering") |
| userId | string | Associated user ID |

```go
type UserAttribute struct {
    ID     string `bson:"_id,omitempty" json:"id"`
    Name   string `bson:"name" json:"name"`
    Value  string `bson:"value" json:"value"`
    UserID string `bson:"user_id" json:"userId"`
}
```

### UserAttributeMapper

Defines how user attributes map to token claims.

| Field | Type | Description |
|-------|------|-------------|
| id | string | Unique identifier (auto-generated) |
| name | string | Mapper name |
| userAttribute | string | Matches UserAttribute.Name |
| tokenClaimName | string | Claim name in token |
| tokenType | string | "id_token", "access_token", "userinfo" |
| multiValued | bool | Support multiple values |
| protocol | string | "openid-connect" |
| clientId | string | Optional scope to client |
| createdAt | time | Creation timestamp |
| updatedAt | time | Last update timestamp |

```go
type UserAttributeMapper struct {
    ID             string         `bson:"_id,omitempty" json:"id"`
    Name           string         `bson:"name" json:"name"`
    UserAttribute  string         `bson:"user_attribute" json:"userAttribute"`
    TokenClaimName string         `bson:"token_claim_name" json:"tokenClaimName"`
    TokenType     string         `bson:"token_type" json:"tokenType"`
    MultiValued   bool           `bson:"multi_valued" json:"multiValued"`
    Protocol      string         `bson:"protocol" json:"protocol"`
    ClientID      string         `bson:"client_id,omitempty" json:"clientId,omitempty"`
    CreatedAt     time.Time      `bson:"created_at" json:"createdAt"`
    UpdatedAt     time.Time      `bson:"updated_at" json:"updatedAt"`
}
```

## Repository Interfaces

### UserAttributeRepository

```go
type UserAttributeRepository interface {
    CreateAttribute(ctx context.Context, attr *UserAttribute) error
    GetAttributeByID(ctx context.Context, id string) (*UserAttribute, error)
    GetAttributesByUserID(ctx context.Context, userID string) ([]*UserAttribute, error)
    UpdateAttribute(ctx context.Context, attr *UserAttribute) error
    DeleteAttribute(ctx context.Context, id string) error
    DeleteAttributesByUserID(ctx context.Context, userID string) error
}
```

### UserAttributeMapperRepository

```go
type UserAttributeMapperRepository interface {
    CreateMapper(ctx context.Context, mapper *UserAttributeMapper) error
    GetMapperByID(ctx context.Context, id string) (*UserAttributeMapper, error)
    GetMappersByTokenType(ctx context.Context, tokenType string) ([]*UserAttributeMapper, error)
    GetMappersForClient(ctx context.Context, clientID string, tokenType string) ([]*UserAttributeMapper, error)
    GetClientMappers(ctx context.Context, clientID string) ([]*UserAttributeMapper, error)
    UpdateMapper(ctx context.Context, mapper *UserAttributeMapper) error
    DeleteMapper(ctx context.Context, id string) error
}
```

## MongoDB Collections

### user_attributes

```json
{
  "_id": "...",
  "name": "department",
  "value": "engineering",
  "user_id": "user-123"
}
```

### user_attribute_mappers

```json
{
  "_id": "...",
  "name": "department_mapper",
  "user_attribute": "department",
  "token_claim_name": "department",
  "token_type": "id_token",
  "multi_valued": false,
  "protocol": "openid-connect",
  "client_id": null,
  "created_at": "2026-04-25T00:00:00Z",
  "updated_at": "2026-04-25T00:00:00Z"
}
```

## GraphQL API

### Types

```graphql
type UserAttribute {
  id: ID!
  name: String!
  value: String!
  userId: ID!
}

type UserAttributeMapper {
  id: ID!
  name: String!
  userAttribute: String!
  tokenClaimName: String!
  tokenType: String!
  multiValued: Boolean!
  protocol: String!
  clientId: ID
}
```

### Inputs

```graphql
input CreateUserAttributeInput {
  name: String!
  value: String!
  userId: ID!
}

input UpdateUserAttributeInput {
  name: String
  value: String
}

input CreateUserAttributeMapperInput {
  name: String!
  userAttribute: String!
  tokenClaimName: String!
  tokenType: String!
  multiValued: Boolean
  protocol: String
  clientId: ID
}

input UpdateUserAttributeMapperInput {
  name: String
  userAttribute: String
  tokenClaimName: String
  tokenType: String
  multiValued: Boolean
  protocol: String
  clientId: ID
}
```

### Queries

```graphql
type Query {
  # Get all attributes for a user
  userAttributes(userId: ID!): [UserAttribute!]!

  # Get all attribute mappers
  userAttributeMappers: [UserAttributeMapper!]!

  # Get attribute mappers for a specific client
  clientUserAttributeMappers(clientId: String!): [UserAttributeMapper!]!
}
```

### Mutations

```graphql
type Mutation {
  # User Attribute Management
  createUserAttribute(input: CreateUserAttributeInput!): UserAttribute!
  updateUserAttribute(id: ID!, input: UpdateUserAttributeInput!): UserAttribute!
  deleteUserAttribute(id: ID!): Boolean!
  deleteUserAttributesByUserId(userId: ID!): Boolean!

  # User Attribute Mapper Management
  createUserAttributeMapper(input: CreateUserAttributeMapperInput!): UserAttributeMapper!
  updateUserAttributeMapper(id: ID!, input: UpdateUserAttributeMapperInput!): UserAttributeMapper!
  deleteUserAttributeMapper(id: ID!): Boolean!
}
```

## Usage Examples

### Create a User Attribute

```graphql
mutation {
  createUserAttribute(input: {
    name: "department",
    value: "engineering",
    userId: "user-123"
  }) {
    id
    name
    value
    userId
  }
}
```

Response:
```json
{
  "data": {
    "createUserAttribute": {
      "id": "6801f1d2b5aa4d3c8c8b4567",
      "name": "department",
      "value": "engineering",
      "userId": "user-123"
    }
  }
}
```

### Create an Attribute Mapper

```graphql
mutation {
  createUserAttributeMapper(input: {
    name: "department_mapper",
    userAttribute: "department",
    tokenClaimName: "department",
    tokenType: "id_token"
  }) {
    id
    name
    userAttribute
    tokenClaimName
    tokenType
  }
}
```

Response:
```json
{
  "data": {
    "createUserAttributeMapper": {
      "id": "6801f1d2b5aa4d3c8c8b4568",
      "name": "department_mapper",
      "userAttribute": "department",
      "tokenClaimName": "department",
      "tokenType": "id_token"
    }
  }
}
```

### Get User Attributes

```graphql
query {
  userAttributes(userId: "user-123") {
    id
    name
    value
  }
}
```

### Get Attribute Mappers for Client

```graphql
query {
  clientUserAttributeMappers(clientId: "my-client") {
    id
    name
    userAttribute
    tokenClaimName
    tokenType
  }
}
```

### Delete User Attribute

```graphql
mutation {
  deleteUserAttribute(id: "6801f1d2b5aa4d3c8c8b4567")
}
```

## Token Generation Flow

When `GenerateIDToken` is called in the token service:

1. User is fetched from the repository
2. Standard claims are added (iss, sub, aud, exp, iat, auth_time, email)
3. Scope-based claims are added (profile → name, preferred_username; email → email, email_verified)
4. **If attribute mappers are configured:**
   - Fetch mappers for the client and token type ("id_token")
   - Fetch user's attributes
   - For each mapper, if the user has a matching attribute, add to claims

Example token claims with attribute:
```json
{
  "iss": "https://auth.example.com",
  "sub": "user-123",
  "aud": "my-client",
  "exp": 1754092800,
  "iat": 1754089200,
  "auth_time": 1754089200,
  "email": "user@example.com",
  "name": "John Doe",
  "preferred_username": "user@example.com",
  "department": "engineering"
}
```

## Configuration

### Token Service Setup

The token service accepts optional repositories for attribute mapping:

```go
tokenService := services.NewTokenService(
    tokenRepo,
    tokenCache,
    issuer,
    signer,
    pubKeyRepo,
    saRepo,
    userRepo,
    userAttrMapperRepo,  // Can be nil
    userAttrRepo,       // Can be nil
    groupRepo,          // Can be nil
    roleRepo,           // Can be nil
)
```

If repositories are nil, attribute mappers and group/role claims are skipped (backward compatible).

## Indexes

### user_attributes

- `{ "user_id": 1 }` - For querying by user
- `{ "user_id": 1, "name": 1 }` - Unique composite for user+name

### user_attribute_mappers

- `{ "token_type": 1 }` - For querying by token type
- `{ "client_id": 1 }` - For querying by client