# Credential Helper for Kubernetes OIDC and Temporary Privilege Escalation

Design for running local tooling against Shadow SSO without long-lived tokens,
and for authenticating `kubectl` / in-cluster workloads through the same issuer.

> Status: design. The server-side prerequisites shipped in **v1.1.0**
> (`client_credentials` audience/subject/groups). The helper itself is not part
> of this repository.

## Goal

1. A local app never holds a long-lived credential or raw token in its config.
2. `kubectl` authenticates through Shadow SSO as an OIDC provider.
3. Short-lived, audience-scoped privilege escalation is possible, with an audit
   trail, without granting standing access.

## What Shadow SSO provides

| Capability | Where |
|---|---|
| Google-style service account JSON (RSA key, `client_email`, `project_id`) | `services/service_account_service.go` |
| `private_key_jwt` client authentication | `api/openidv2_1/handlers.go` (`authenticateWithJWT`) |
| `client_credentials` grant with SA roles | `services/oauth_service.go` |
| RFC 8707 `audience` / `resource` | v1.1.0 |
| Non-empty `sub`, `groups` claim on SA tokens | v1.1.0 |
| OIDC discovery + JWKS | `/.well-known/openid-configuration`, `/.well-known/jwks.json` |
| RFC 8693 token exchange (interface) | `domain/oauth_service.go` — `TokenExchange` |

See [client_credentials_audience_groups.md](./client_credentials_audience_groups.md)
for provisioning and kube-apiserver flags.

## Components

```
┌──────────────┐   exec + JSON   ┌──────────────────┐   HTTPS    ┌─────────────┐
│ app / kubectl│ ──────────────► │  sso-cred        │ ─────────► │ Shadow SSO  │
│ (no secrets) │ ◄────────────── │  (cred helper)   │ ◄───────── │  token EP   │
└──────────────┘  short token    └────────┬─────────┘  JWT       └─────────────┘
                                          │
                              ┌───────────┴────────────┐
                              │ sso-agent (optional)   │
                              │ unix socket, cache,    │
                              │ escalation broker      │
                              └───────────┬────────────┘
                                          │
                              ┌───────────┴────────────┐
                              │ OS keychain:           │
                              │ service account JSON   │
                              └────────────────────────┘
```

### `sso-cred`

One static binary, no daemon required to start.

```
sso-cred login --from ./sa.json                              # import + encrypt, shred source
sso-cred get-token --audience kubernetes --cluster prod      # ExecCredential v1
sso-cred get --server registry.pilab.hu                      # docker-credential protocol
sso-cred exec --as-audience timesheet-grpc -- myapp          # inject into child env
sso-cred escalate --cluster prod --role cluster-admin --ttl 15m --reason INC-1234
sso-cred status / revoke
```

Credential storage is the OS keychain (macOS Keychain, libsecret, Credential
Manager) with an `age`-encrypted file as fallback. The SA private key never
leaves the helper process; callers only ever receive short-lived access tokens.
Configuration files hold non-secrets only (`issuer`, `default_audience`,
`agent_socket`, `allowed_escalations`).

### `sso-agent` (optional)

A unix socket (`0600`, peer-UID checked) for token caching, single-flight refresh
and the escalation approval UX. The helper falls back to doing the work itself
when the socket is absent.

## Flow: base token

RFC 7523 client assertion, then `client_credentials`:

```
claims: iss=sub=client_email, aud=<token endpoint>, exp=+5m, jti=<uuid>
POST /oauth2/token
  grant_type=client_credentials
  client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer
  client_assertion=<signed JWT>
  audience=kubernetes
```

Cache key `(client_email, audience, scope)`, refresh at 80% of TTL, never
persisted. Base tokens: 10–15 minutes.

## Flow: Kubernetes

kubeconfig uses the client-go exec plugin:

```yaml
users:
- name: sso
  user:
    exec:
      apiVersion: client.authentication.k8s.io/v1
      command: /usr/local/bin/sso-cred
      args: ["get-token", "--cluster", "prod", "--audience", "kubernetes"]
      interactiveMode: IfAvailable
      provideClusterInfo: true
```

`get-token` prints an `ExecCredential` and exits; kubectl re-invokes it near
`expirationTimestamp`.

## Flow: temporary privilege escalation

The constraint that shapes the design: **kube-apiserver derives groups from the
token and never introspects it.** `exp` is the revocation control, so elevation
must be short-lived by construction.

```
base token      groups=[sso:k8s-view]              ttl 15m   automated
elevated token  groups=[sso:k8s-view,sso:k8s-admin] ttl 5-15m approved, aud-bound
```

1. `sso-cred escalate --cluster prod --role cluster-admin --ttl 15m --reason INC-1234`
2. Helper sends an RFC 8693 token exchange:

   ```
   grant_type=urn:ietf:params:oauth:grant-type:token-exchange
   subject_token=<base token>
   subject_token_type=urn:ietf:params:oauth:token-type:access_token
   audience=kubernetes
   scope=sso:escalate:cluster-admin
   ```

3. SSO policy evaluates who may escalate to what, optionally requires a step-up
   (fresh MFA / `acr`), caps the TTL, and mints a token carrying elevated
   `groups`, `act: {sub: <client_email>}` and a `grant_id`.
4. SSO writes an audit event: subject, grant, scope, reason, approver, expiry.
5. The helper keeps the elevated token in memory only and never overwrites the
   base credential.

Required controls:

- No self-approval for privileged scopes: two-person or MFA step-up.
- TTL capped server-side; the requested TTL is a request, not a grant.
- Audience-bound tokens, so a k8s token cannot be replayed at gRPC services.
- Break-glass path with mandatory reason, immediate alert, hard TTL.
- Optional revocation: a `SubjectAccessReview`-backed webhook authorizer keyed by
  `jti` / `grant_id` when 15 minutes is too long.

## Anti-patterns

- Private key in environment variables or project config.
- Access tokens in `~/.config/*.yaml` (world-readable by default).
- A second long-lived credential for elevation — turns a 15-minute window into a
  permanent one.
- Logging tokens, or echoing them into shell history.

## Roadmap

1. ~~SSO: audience, non-empty `sub`, `groups`~~ (v1.1.0)
2. `sso-cred` with keychain storage, `get-token`, ExecCredential.
3. Token exchange + escalation policy + audit.
4. `sso-agent` (shared cache, approval UX).
5. Workload Identity: pods present their projected k8s SA token to SSO's
   `jwt-bearer` grant, removing the static key entirely.
