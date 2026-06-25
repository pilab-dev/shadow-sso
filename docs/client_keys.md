# OAuth Client Key Management

This document describes the OAuth client key management system in shadow-sso, including JWKS, client certificates, and key generation.

## Overview

Shadow SSO supports public key authentication for OAuth clients using JSON Web Key Sets (JWKS). Clients can have RSA key pairs generated dynamically or configured with existing keys.

## Data Model

### JWKS (JSON Web Key Set)

Represents a set of cryptographic keys for a client.

```go
type JWKS struct {
    Keys []JSONWebKey `json:"keys"`
}
```

### JSONWebKey

Represents a single RSA key in JWK format.

```go
type JSONWebKey struct {
    Kid string `json:"kid"`     // Key ID
    Kty string `json:"kty"`     // Key type (RSA)
    Alg string `json:"alg"`     // Algorithm (RS256)
    Use string `json:"use"`     // Key usage (sig)
    N   string `json:"n"`     // RSA modulus (base64url)
    E   string `json:"e"`     // Public exponent
    
    // Private key components (only included when generating)
    P   string `json:"p,omitempty"` // Prime P
    Q   string `json:"q,omitempty"` // Prime Q
    D   string `json:"d,omitempty"` // Private exponent
    Qi  string `json:"qi,omitempty"` // CRT coefficient
    Dq  string `json:"dq,omitempty"` // CRT exponent 1
    Dp  string `json:"dp,omitempty"` // CRT exponent 2
}
```

### Client Model Extensions

The OAuth client supports JWKS configuration:

```go
type Client struct {
    // ... other fields
    JWKS     *domain.JWKS  `bson:"jwks,omitempty" json:"jwks,omitempty"`
    JWKSURI  string    `bson:"jwks_uri,omitempty" json:"jwksUri,omitempty"`
}
```

## Use Cases

### 1. Client Authentication with JWTs

Clients can authenticate using signed JWTs instead of client secrets:

```
POST /oauth2/token
Content-Type: application/x-www-form-urlencoded

grant_type=client_credentials
&client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer
&client_assertion=<JWT>
```

The JWT must be signed with the client's private key.

### 2. Token Endpoint Authentication

Confidential clients can use private_key_jwt authentication method.

## GraphQL API

### Query Fields

```graphql
type Client {
    # JWKS directly embedded in client
    jwks: JSON
    
    # JWKS URI for remote key fetching
    jwksUri: String
}
```

### Mutations

#### Generate Client Secret

Generates a new client secret.

```graphql
mutation {
    generateClientSecret(clientId: "client-123") {
        # Returns the new secret
    }
}
```

#### Generate Client Keys

Generates a new RSA key pair for the client.

```graphql
mutation {
    generateClientKeys(
        clientId: "client-123",
        keyType: "RSA",   # Optional: key type
        keyBits: 2048      # Optional: key size (2048 or 4096)
    ) {
        # Returns JWKS as JSON string
    }
}
```

Example response:
```json
{
  "keys": [
    {
      "kid": "client-123-a1b2c3d4",
      "kty": "RSA",
      "alg": "RS256",
      "use": "sig",
      "n": "base64url-modulus...",
      "e": "AQAB",
      "d": "base64url-private-exponent...",
      "p": "base64url-prime-p...",
      "q": "base64url-prime-q..."
    }
  ]
}
```

## Key Rotation

### Manual Rotation via GraphQL

1. Generate new keys:
```graphql
mutation {
    generateClientKeys(clientId: "client-123", keyBits: 4096)
}
```

2. Update client to use new keys (the keys are automatically stored)

3. Old keys remain valid until explicitly removed

### Programmatic Rotation

The client can retrieve JWKS from:
- `client.jwks` - Embedded JWKS
- `client.jwksUri` - Remote JWKS URI

## Client Authentication Flow

### Using Private Key JWT

1. Client creates a JWT with claims:
```json
{
    "iss": "client-id",
    "sub": "client-id", 
    "aud": "https://sso.example.com/oauth2/token",
    "iat": 1754092800,
    "exp": 1754096400,
    "jti": "unique-token-id"
}
```

2. Client signs with private key using RS256

3. Client sends to token endpoint:
```
POST /oauth2/token
grant_type=client_credentials
&client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer
&client_assertion=<signed-jwt>
```

4. Server validates:
   - Verifies signature using client's public key from JWKS
   - Validates claims (iss, aud, exp)
   - Issues tokens

## Security Considerations

### Key Storage
- Private keys are stored encrypted in MongoDB
- Only the client that owns the keys can retrieve them
- Keys are never logged or exposed in error messages

### Key Sizes
- Minimum 2048-bit RSA recommended
- 4096-bit for high-security requirements

### Key IDs
- Each key has unique `kid` for key identification
- Key ID included in JWT header for key selection
- Server can have multiple valid keys for rotation

## MongoDB Collection

### oauth_clients

```json
{
    "_id": "client-123",
    "client_id": "my-client",
    "name": "My Application",
    "jwks": {
        "keys": [
            {
                "kid": "client-123-a1b2c3d4",
                "kty": "RSA",
                ...
            }
        ]
    },
    "jwks_uri": "https://myapp.example.com/.well-known/jwks.json"
}
```

## Related Documentation

- [User Attributes](./user_attributes.md) - Attribute mappers for token claims
- [API Documentation](./api.md) - gRPC API reference
- [GraphQL Schema](../graphql/schema.graphqls) - Full GraphQL schema