# Realm Keys Management

This document describes realm signing keys in shadow-sso for JWT token issuance.

## Overview

Realm keys are used to sign JWT tokens (access tokens, ID tokens, refresh tokens) issued by the server. Multiple keys can be configured for key rotation.

## Data Model

### RealmKey

Represents a signing key for the realm.

| Field | Type | Description |
|-------|------|-------------|
| id | string | Unique identifier |
| name | string | Key name |
| type | string | Key type (RSA, EC) |
| providerId | string | Key provider identifier |
| active | bool | Whether key is active for signing |
| priority | int | Key priority (lower = higher priority) |
| publicKey | string | Public key in PEM format |
| privateKey | string | Private key in PEM format (secret) |
| certificate | string | X.509 certificate |

```go
type RealmKey struct {
    ID          string `bson:"_id,omitempty" json:"id"`
    Name        string `bson:"name" json:"name"`
    Type        string `bson:"type" json:"type"`         // RSA, EC
    ProviderID string `bson:"provider_id" json:"providerId"`
    Active      bool   `bson:"active" json:"active"`
    Priority   int    `bson:"priority" json:"priority"`
    PublicKey  string `bson:"public_key,omitempty" json:"publicKey,omitempty"`
    PrivateKey string `bson:"private_key,omitempty" json:"privateKey,omitempty"`
    Certificate string `bson:"certificate,omitempty" json:"certificate,omitempty"`
}
```

## Key Types

### RSA Keys

- Most common type
- 2048-bit or 4096-bit
- RS256, RS384, RS512 algorithms

### EC (Elliptic Curve) Keys

- More efficient than RSA
- P-256, P-384, P-521 curves
- ES256, ES384, ES512 algorithms

## Key Rotation

### Active Key Selection

1. Server selects highest priority active key to sign new tokens
2. Multiple active keys = server rotates automatically
3. JWT `kid` header indicates which key was used

### Rotation Process

1. Generate new key with higher priority
2. Deploy new public key to resource servers
3. Keep old key active until all tokens expire
4. Remove old key after TTL expires

## GraphQL API

### Queries

```graphql
# Get all realm keys
realmKeys: [RealmKey!]!
```

### Mutations

```graphql
# Update realm keys
updateRealmKeys(input: UpdateRealmKeysInput!): [RealmKey!]!
```

### Input Type

```graphql
input UpdateRealmKeysInput {
    keys: [RealmKeyInput!]!
}

input RealmKeyInput {
    name: String!
    type: String!
    providerId: String!
    active: Boolean!
    priority: Int!
    publicKey: String
    privateKey: String  
    certificate: String
}
```

## Usage Examples

### List Realm Keys

```graphql
query {
    realmKeys {
        id
        name
        type
        active
        priority
        publicKey
    }
}
```

Example response:
```json
{
  "data": {
    "realmKeys": [
      {
        "id": "key-1",
        "name": "rsa-key-1",
        "type": "RSA",
        "active": true,
        "priority": 1,
        "publicKey": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----"
      }
    ]
  }
}
```

### Add New Key

```graphql
mutation {
    updateRealmKeys(input: {
        keys: [
            {
                name: "rsa-key-2",
                type: "RSA",
                providerId: "default",
                active: true,
                priority: 0,
                publicKey: "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----",
                privateKey: "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----"
            }
        ]
    }) {
        id
        name
        active
    }
}
```

### Rotate Keys (Add New, Keep Old)

```graphql
mutation {
    updateRealmKeys(input: {
        keys: [
            {
                id: "existing-key-id",  # Keep existing
                name: "rsa-key-1",
                type: "RSA", 
                providerId: "default",
                active: true,
                priority: 2
            },
            {
                name: "rsa-key-2",  # Add new
                type: "RSA",
                providerId: "default", 
                active: true,
                priority: 1,
                publicKey: "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----",
                privateKey: "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----"
            }
        ]
    }) {
        id
        name
        priority
    }
}
```

## JWT Verification

### Public Key Endpoints

Resource servers can retrieve public keys from:

1. **JWKS Endpoint**: `/.well-known/jwks.json`
2. **Embedded in Discovery**: `/.well-known/openid-configuration`

### Example JWKS Response

```json
{
    "keys": [
        {
            "kid": "key-123",
            "kty": "RSA",
            "alg": "RS256",
            "use": "sig",
            "n": "base64url-modulus...",
            "e": "AQAB"
        }
    ]
}
```

### Validation

1. Extract `kid` from JWT header
2. Fetch public key from JWKS endpoint
3. Verify signature
4. Validate claims (iss, aud, exp)

## Key Generation

### OpenSSL Commands

Generate RSA key:
```bash
# Generate private key
openssl genrsa -out private.pem 2048

# Extract public key  
openssl rsa -in private.pem -pubout -out public.pem

# Create PKCS#12 (optional)
openssl pkcs12 -export -in cert.pem -inkey private.pem -out keystore.p12
```

### Programmatic Generation

Use GraphQL to generate client keys (for client authentication):
```graphql
mutation {
    generateClientKeys(clientId: "temp-client", keyBits: 4096)
}
```

## MongoDB Collection

### realm_keys

```json
{
    "_id": "key-123",
    "name": "rsa-key-1",
    "type": "RSA",
    "provider_id": "default",
    "active": true,
    "priority": 1,
    "public_key": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----",
    "private_key": "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----",
    "certificate": null
}
```

## Security Considerations

### Private Key Storage
- Stored encrypted in MongoDB
- Never exposed in logs or error messages
- Access restricted to token signing service

### Key Management
- Regular key rotation recommended
- Old keys should remain active during token TTL
- Monitor key expiration dates

## Related Documentation

- [Client Keys](./client_keys.md) - Client JWKS for client auth
- [Protocol Mappers](./protocol_mappers.md) - Token claim mapping
- [Token Service](../services/token_service.go) - Token generation