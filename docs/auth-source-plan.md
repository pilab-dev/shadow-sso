# Pluggable authentication and attribute sources

**Status:** Draft plan  
**Scope:** Replace the hardwired "local Mongo user + bcrypt" login path with a
modular authentication pipeline whose source of truth can be an external
directory (the PiDirectory AD fork) while keeping the local store as the
open-source default and fallback.

Related: [LDAP user repository plan](ldap-user-repository-plan.md),
[federation](federation.md), [MFA management](mfa-management.md).

---

## 1. Goals and non-goals

### Goals

- Directory (PiDirectory) is the source of truth for accounts, groups,
  attributes, credentials and Kerberos tickets.
- ShadowSSO remains the token issuer and session/device/offline-token owner.
- Authentication sources are pluggable through small interfaces.
- Account state and policy come from an attribute source, not from local flags.
- Local Mongo storage remains the default for a fresh open-source install and
  the break-glass fallback in a directory deployment.
- The design is understandable to contributors: one contract package, one
  adapter per source, no hidden global state.

### Non-goals

- Replacing the token/session/device stores with the directory.
- Storing directory passwords locally.
- Making Go plugins mandatory. Sources are registered at compile time, with an
  optional generic HTTP/gRPC adapter for out-of-process sources.

---

## 2. Current state

| Concern | Today |
|---|---|
| User store | MongoDB, `shadow_sso_db.oauth_users` |
| Password check | `bcrypt` against `oauth_users.password_hash` |
| Login decision | `internal/authflow.Runner` returns only `requiresMFA bool` |
| External IdPs | `internal/federation` (`OAuth2Provider`) and `domain.IdentityProvider` |
| LDAP | bind/search/bind works, but `LDAPLoginHandler` never provisions a user or issues tokens |
| Required actions | `graphql.executeActions` is a stub; no `User.RequiredActions` |
| Kerberos | none |
| Token claims | no `amr`/`acr`/source claim |

The repository abstractions (`domain.UserRepository`,
`services.RepositoryProvider`) exist, but only MongoDB is wired; the DTS
backend is explicitly disabled at startup.

---

## 3. Contracts

Put the contracts in a small package with no server dependencies:
`internal/authsource`.

```go
package authsource

// Authenticator proves identity. It does not decide policy.
type Authenticator interface {
    ID() string
    Supports(ctx context.Context, identifier string) bool
    Authenticate(ctx context.Context, req AuthRequest) (*Identity, error)
}

type Identity struct {
    SourceID   string // "local", "pdirectory", "ldap"
    ExternalID string // stable directory identifier
    Identifier string // what the user typed
}

type AuthRequest struct {
    Identifier string
    Password   string
    Kerberos   []byte // SPNEGO token, when present
    ClientID   string
    RemoteIP   string
}

// AttributeSource is the source of truth for account state and policy inputs.
type AttributeSource interface {
    ID() string
    GetAccount(ctx context.Context, id *Identity) (*Account, error)
    Capabilities() Capabilities
}

type Account struct {
    ExternalID  string
    Username    string
    Email       string
    DisplayName string

    Enabled         bool
    Locked          bool
    LockoutReason   string
    PasswordExpired bool

    MFARequired       bool
    AllowedMFAMethods []string
    RequiredActions   []string
    Groups            []string
    Attributes        map[string][]string

    UpdatedAt time.Time
}

type Capabilities struct {
    SetPassword bool
    SetPhone    bool
    SetEmail    bool
    SyncGroups  bool
}
```

A `Source` bundles the two so routing stays obvious:

```go
type Source struct {
    ID            string
    Authenticator Authenticator
    Attributes    AttributeSource
    Priority      int
    Domains       []string
}
```

Sources register through a registry, e.g. `authsource.Register("pdirectory",
factory)`. A build with only `local` registered behaves exactly like today.

---

## 4. Login pipeline

```
identifier
  → SourceRouter (domain/tenant/priority; local last)
  → Authenticator.Authenticate            (password, Kerberos, ...)
  → AttributeSource.GetAccount            (authoritative state)
  → policy.Evaluate                       (enabled, locked, expiry, actions)
  → provisioning.Resolve                  (link or JIT-create local user)
  → MFA decision                          (directory + realm + local)
  → required-action pages                 (blocking first)
  → session/tokens                        (sub = local user ID, amr/acr/source)
```

`internal/authflow.Runner` must stop returning only a boolean and return a
decision instead:

```go
type Decision struct {
    User              *domain.User
    Identity          *authsource.Identity
    Account           *authsource.Account
    AMR               []string // pwd, krb, otp, mfa
    ACR               string
    MFARequired       bool
    AllowedMFAMethods []string
    RequiredActions   []requiredaction.Action
}
```

---

## 5. Source of truth vs local overlay

| Owned by the directory | Owned by ShadowSSO |
|---|---|
| Account existence, enabled/locked | `user_id`, sessions, refresh/offline tokens |
| Password / Kerberos credential | MFA secrets, recovery codes, WebAuthn devices |
| Groups and attributes | Role mapping result, consent, audit |
| Password expiry and required actions | Token claims and client scopes |
| Phone/email (optionally) | Device inventory and push tokens |

Directory passwords are never stored locally. On login, the directory
authenticates; SSO stores an account link (`source_id`, `external_id`) and a
short-TTL attribute snapshot.

### Fallback semantics

- Directory-backed users fail closed when the directory is unreachable.
- `local` is always available for break-glass and admin accounts.
- Default routing: by email domain; `local` handles everything else.
- Disable/lock detected at login and on a configurable refresh-token TTL;
  revoke sessions when the account is no longer valid.

---

## 6. Required actions

The directory returns action names; SSO maps them to handlers:

```go
type Action string

const (
    ActionUpdatePassword Action = "UPDATE_PASSWORD"
    ActionConfigureTOTP  Action = "CONFIGURE_TOTP"
    ActionUpdatePhone    Action = "UPDATE_PHONE"
    ActionVerifyEmail    Action = "VERIFY_EMAIL"
)

type Handler interface {
    Name() Action
    Blocking() bool
    Execute(ctx context.Context, flow *domain.LoginFlowState, user *domain.User, account *authsource.Account) error
}
```

- Blocking actions run before `completeLogin`.
- Non-blocking actions appear on the account page after login.
- Writes use `Capabilities`; if the directory cannot write, fail with an
  explicit administrator message instead of silently skipping.
- `CONFIGURE_TOTP` / `CONFIGURE_WEBAUTHN` reuse the enrollment code already in
  `api/webauth`.
- `domain.User` gains `RequiredActions []string` and the GraphQL
  `executeActions` resolver becomes real.

---

## 7. Kerberos

Implement Kerberos as one `Authenticator`, not a parallel auth system:

- `KerberosAuthenticator.Authenticate` validates a SPNEGO `Negotiate` token
  with a keytab (`github.com/jcmturner/gokrb5/v8`) and returns
  `Identity{ExternalID: principal}`.
- `/login` challenges with `WWW-Authenticate: Negotiate`; without a ticket the
  password form remains available.
- `AttributeSource.GetAccount` resolves the principal in the directory.
- Optional KRB5 password pre-auth for non-domain-joined machines.
- Config: realm, SPN, keytab (file or secret reference), enctype allowlist,
  clock-skew policy.
- `amr` includes `krb`; MFA step-up remains policy-driven.

Operational prerequisites: DNS/SPN, keytab rotation, time sync, realm trusts,
HTTPS, and browser `Negotiate` policy on domain-joined clients.

---

## 8. Package layout

```
internal/authsource/
  contracts.go        // interfaces and types
  registry.go         // source registration
  router.go           // domain/tenant routing, priority, fallback
  local/              // current Mongo + bcrypt behavior
  ldap/               // LDAP/AD adapter (reuse federation LDAP client)
  pdirectory/         // PiDirectory adapter (HTTP/gRPC)
  kerberos/           // SPNEGO authenticator
  extauth/            // generic out-of-process adapter
internal/policy/      // gates and precedence
internal/provisioning/ // account links, JIT users, attribute cache
internal/requiredaction/ // action registry and handlers
internal/authflow/    // orchestration, flow executions
```

Only `local` is registered in the default build.

---

## 9. Configuration sketch

```yaml
auth:
  routing:
    mode: directory-first   # directory-first | local-only | hybrid
    default_source: local
    domain_routes:
      "corp.example.com": pdirectory
  sources:
    pdirectory:
      type: directory
      endpoint: https://dir.internal/api
      token: ${PDIRECTORY_TOKEN}
      attribute_cache_ttl: 60s
      write_capabilities: [set_password, set_phone]
      kerberos:
        enabled: true
        realm: CORP.EXAMPLE.COM
        spn: HTTP/sso.example.com
        keytab: /etc/sso/http.keytab
    local:
      type: local
      fallback: true
```

---

## 10. Policy precedence

Most restrictive wins:

| Field | Rule |
|---|---|
| `Enabled` | Directory disabled always wins; local cannot re-enable |
| `Locked` | Either source locks; reason visible to admins only |
| `MFARequired` | OR of directory, realm and user flags |
| `AllowedMFAMethods` | Intersection; empty means deny with an explicit error |
| `RequiredActions` | Union; blocking wins |
| `PasswordExpired` | Directory wins |

MFA secrets never leave SSO. The directory only states requirements.

---

## 11. Phases

| Phase | Deliverable | Days |
|---|---|---|
| 0 | Contracts, registry, `local` adapter; no behavior change | 3–4 |
| 1 | Policy gates, provisioning/link, attribute cache, `amr` claims | 3–4 |
| 2 | PiDirectory adapter, router, password login integration | 3–5 |
| 3 | Required-action framework and pages | 3–5 |
| 4 | Kerberos SPNEGO + fallback + tests | 5–8 |
| 5 | Deprovisioning, token revalidation, metrics, adapter guide | 3–4 |
| **Total** | | **~3–4 weeks** |

Directory password + gates + forced TOTP demo: ~1.5–2 weeks.

---

## 12. Open questions

1. PiDirectory protocol: REST, gRPC, or LDAP? Exact account+policy call.
2. Does the directory own passwords, or only Kerberos? Password-change support?
3. Routing: email domain, tenant, per-client, or multiple directories?
4. Fallback when the directory is down: local break-glass only, or cached
   directory sign-in?
5. Which required actions are blocking vs post-login, and which are writable?
6. Groups → roles: directory-provided roles or SSO-side mapping?
7. Kerberos scope: browser SPNEGO only, or password-based KRB5 too? Cross-realm?
8. Can the directory require/forbid specific MFA methods? What happens when it
   requires WebAuthn, which the server cannot verify yet?
9. Deprovisioning: webhook/event stream or polling?
10. On disable/lock: revoke sessions immediately or at refresh?
