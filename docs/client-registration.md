# Registering an OIDC Client in Shadow SSO

Clients (relying parties) are managed via the Shadow SSO GraphQL API, available on the management port (default `:5000`, mapped to `:5001` in Docker).

All mutations require an `Authorization: Bearer <bootstrap-token>` header.  
The bootstrap token is set via the `SSSO_BOOTSTRAP_TOKEN` environment variable.

---

## 1. Create the client

`createClient` accepts a `CreateClientInput`. The `clientSecret` field in the input is **ignored by the resolver** — set the secret separately using `generateClientSecret` (step 2).

```graphql
mutation CreatePiratClient {
  createClient(input: {
    clientId: "my-app"
    clientName: "My Application"
    description: "OIDC relying party for My Application"

    # authorization_code for web login; add refresh_token to support token refresh
    allowedGrantTypes: ["authorization_code", "refresh_token"]

    # Must exactly match the redirect URI the app sends in the auth request
    redirectUris: ["https://my-app.example.com/login/sso/callback"]

    # Scopes the client may request
    scope: ["openid", "email", "profile"]

    # confidential = requires client_secret; public = PKCE-only (SPA/mobile)
    publicClient: false

    # client_secret_basic  → secret in Authorization header (recommended)
    # client_secret_post   → secret in POST body
    # none                 → public client, no secret
    # (field name in GraphQL — maps to token_endpoint_auth_method in OIDC)

    standardFlowEnabled: true
  }) {
    id
    clientName
  }
}
```

**curl example:**

```bash
curl -s -X POST http://localhost:5001/graphql \
  -H "Authorization: Bearer $SSSO_BOOTSTRAP_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "query": "mutation { createClient(input: { clientId: \"my-app\", clientName: \"My Application\", allowedGrantTypes: [\"authorization_code\", \"refresh_token\"], redirectUris: [\"https://my-app.example.com/login/sso/callback\"], scope: [\"openid\", \"email\", \"profile\"], publicClient: false, standardFlowEnabled: true }) { id clientName } }"
  }'
```

The response contains the client's internal `id` (a UUID) and the `clientId` you chose.  
Use the `clientId` string (e.g. `"my-app"`) everywhere in OIDC flows.

---

## 2. Set the client secret

`createClient` does **not** store the `clientSecret` field from the input. After creation, call `generateClientSecret` to produce and store a bcrypt-hashed secret. The mutation returns the **plaintext secret once** — store it securely, as it cannot be retrieved again.

```graphql
mutation {
  generateClientSecret(clientId: "my-app")
}
```

**curl example:**

```bash
curl -s -X POST http://localhost:5001/graphql \
  -H "Authorization: Bearer $SSSO_BOOTSTRAP_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"query": "mutation { generateClientSecret(clientId: \"my-app\") }"}'
```

Response:

```json
{ "data": { "generateClientSecret": "xxxxxxxxxxxxxxxxxxxxxxxxxxx" } }
```

This returned value is the `CLIENT_SECRET` to configure in your relying party.

> **Note:** `generateClientSecret` calls `UpdateClient` internally. If you see a MongoDB error about `$` operator keys in a replacement document, apply the fix in [`mongodb/client_repository.go`](../mongodb/client_repository.go) (change `ReplaceOne(ctx, filter, bson.M{"$set": c})` → `ReplaceOne(ctx, filter, c)`) and rebuild the image.

---

## 3. Verify the client

```bash
curl -s -X POST http://localhost:5001/graphql \
  -H "Authorization: Bearer $SSSO_BOOTSTRAP_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "query": "{ clients { edges { node { id clientName allowedGrantTypes redirectUris } } } }"
  }'
```

---

## Key fields reference

| Field | Description |
|---|---|
| `clientId` | Machine-readable ID used in OIDC requests (`client_id` parameter) |
| `clientName` | Human-readable name shown on consent screens |
| `allowedGrantTypes` | `authorization_code`, `refresh_token`, `client_credentials`, `password` |
| `redirectUris` | Allowed callback URLs after successful authentication (exact match) |
| `scope` | Scopes this client may request: `openid`, `email`, `profile`, custom |
| `publicClient` | `true` for SPA/mobile (PKCE only, no secret); `false` for server-side apps |
| `standardFlowEnabled` | Enables the authorization_code flow |

---

## OIDC discovery

Once shadow-sso is running, the standard discovery document is at:

```
http://<host>:<port>/.well-known/openid-configuration
```

Relying parties should use this URL as the `issuer` and fetch endpoints from it automatically.
