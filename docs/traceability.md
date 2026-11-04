# Traceability and Browser Baseline

Shadow SSO exposes three related views for operators:

| View | Question it answers | Storage |
|---|---|---|
| **Devices** (sessions) | Which browser/agent is signed in, from where, and how recently? | `sessions` |
| **Tokens** | Which access/refresh tokens exist for a user, when do they expire, and are they revoked or rotated? | `tokens` |
| **Audit events** | What happened: login, token issuance, refresh, revocation, session kick, browser block? | `audit_events` |

All three are available through `ssoctl` over ConnectRPC. Token values and
secrets are never returned, logged, or persisted in audit details.

## Stream audit events (`ssoctl audit follow`)

`audit follow` behaves like `kubectl logs -f`: it replays a window, then keeps
the stream open.

```bash
# Replay the last 15 minutes, then follow live
ssoctl audit follow

# Start immediately and only show new events
ssoctl audit follow --since now

# kubectl-style: list + follow
ssoctl audit list -f --user alice@example.com

# Focus on one user or action
ssoctl audit follow --user alice@example.com --since 1h
ssoctl audit follow --action TokenRefreshed --since 30m

# NDJSON for jq/Vector/Loki
ssoctl audit follow --json --since 5m | jq -c .

# Poll less aggressively on a large deployment
ssoctl audit follow --interval-ms 5000
```

The server polls the audit store, not an in-process bus, so a follower sees
events written by **every** replica. Consecutive events at the same timestamp
are de-duplicated by event ID.

### Actions worth alerting on

| Action | Meaning |
|---|---|
| `LoginComplete` | Password (+MFA) login succeeded and a session/token pair was created |
| `TokenIssued` | Access/refresh token created |
| `TokenRefreshed` | Refresh rotation succeeded |
| `RefreshTokenReplay` | A used refresh token was presented again; family + session revoked |
| `TokenRevoked` | A token was revoked explicitly |
| `TokenExpired` | A token crossed its expiry boundary (sweeper) or an expired refresh token was presented |
| `SessionKicked` | A device/session was revoked (single or all) |
| `BrowserBlocked` | Interactive login rejected by the browser baseline |
| `BrowserPolicyWarn` | Browser violated the policy, but `warn` mode allowed it |
| `BrowserPolicyUpdated` / `BrowserPolicyReset` | Policy changed |

## Inspect a user's tokens

```bash
# Self
ssoctl token list

# Admin looking at another user, including dead tokens
ssoctl token list --user-id alice@example.com --all

# Narrow by type, session or client
ssoctl token list --type refresh_token
ssoctl token list --session <session-id>
ssoctl token list --client my-web-app

# One token by JTI
ssoctl token get <jti>

# Emergency revocation (audited)
ssoctl token revoke <jti> --reason "laptop lost"
```

The listing shows JTI, type, status (`ACTIVE`, `REVOKED`, `EXPIRED`,
`ROTATED`), client, session, parsed device, issue and expiry times. Refresh
token families are visible through `family`, `parent_jti` and `rotated_to`.

## Inspect a user's devices / browsers / agents

```bash
ssoctl device list
ssoctl device list --user-id alice@example.com --all
ssoctl device show <session-id>
```

`device list` shows the parsed browser family and version, OS, device class,
IP, last use, active/total token counts, revocation state, and marks the
current CLI session with `*`. `device show` also prints the tokens belonging
to that device.

Web authorization-code logins create a session when the authorization code is
issued, so the browser appears in `device list` and the tokens returned by the
code exchange carry its `sid`.

The older `ssoctl session list` command now includes the same parsed
browser/OS/device fields.

## Browser baseline (enterprise)

The browser baseline refuses interactive logins from browsers older than the
configured minimum version. It is intended for environments that require
patched browsers (for example, an insurance or healthcare tenant).

```bash
# Inspect
ssoctl browser-policy show

# Test a User-Agent before rolling out
ssoctl browser-policy check "Mozilla/5.0 ... Chrome/90.0 ..."

# Safe rollout: observe violations without blocking
ssoctl browser-policy set --enabled --enforcement warn --block-bots

# After reviewing BrowserPolicyWarn events, enforce
ssoctl browser-policy set --enforcement block

# Tighten specific families (major versions)
ssoctl browser-policy set --min chrome=126 --min edge=126 --min firefox=128 --min safari=17.5

# Exempt a corporate updater or health checker (case-insensitive substring)
ssoctl browser-policy set --exempt "MyCorpUpdater/" --exempt "kube-probe/"

# Remove the policy
ssoctl browser-policy reset
```

### Defaults

Built-in minimum major versions (used when the policy has no explicit entry):

| Browser | Minimum |
|---|---|
| Chrome | 120 |
| Edge | 120 |
| Firefox | 121 |
| Safari | 17.2 |
| Opera | 106 |
| Samsung Internet | 23 |

These are conservative defaults, not a statement about the current stable
release. Update them with `--min` as your patch baseline moves.

### What is enforced

- `GET/POST /login`, `/oauth2/authorize`, `/oauth2/silent-authorize`, `/mfa`,
  `/consent` — HTTP middleware.
- `AuthService.Login` and `AuthService.Verify2FA` — ConnectRPC handlers, so CLI
  and programmatic browser login cannot bypass the web page.
- `/oauth2/token`, `/oauth2/introspect`, `/oauth2/revoke` and other machine
  endpoints are **not** browser-checked.

### Exemptions

`ssoctl`, `curl`, `wget`, Go/Python/OkHttp/Postman HTTP clients, `grpc-go`,
`connect-go`, Kubernetes probes and ELB health checks are exempt by default.
This is deliberate: `BlockUnknown` must never take down service accounts,
health checks or CI. Add tenant-specific agents with `--exempt`.

### Audit and rollout

In `warn` mode a violating login is allowed but emits `BrowserPolicyWarn`. Use
`audit follow --action BrowserPolicyWarn` to see who would be affected, then
switch to `block`. Blocked attempts emit `BrowserBlocked` with the UA, IP and
reason. Neither event contains credentials.

## API surface

| Service | Methods |
|---|---|
| `AuditService` | `ListAuditEvents`, `FollowAuditEvents` (server stream) |
| `TokenService` | `ListUserTokens`, `GetToken`, `ListUserDevices`, `RevokeToken` |
| `BrowserPolicyService` | `GetBrowserPolicy`, `UpdateBrowserPolicy`, `CheckBrowser` |

Self-vs-admin authorization is enforced in the service (`me` or own user ID;
admins need `sessions:list_others` / `sessions:clear_others`). Audit and
browser-policy reads require admin permissions; policy updates additionally
require `browser_policy:manage`.

## Limitations

- Token listing requires a token store that implements
  `domain.TokenQueryRepository` (the MongoDB store does). A DTS-backed store
  returns `Unimplemented` for listing; issuance, validation and revocation keep
  working.
- Audit follow reflects persisted events. If the audit sink is unavailable, the
  event is still written to stdout but cannot be followed until the store
  recovers.
- The browser policy is realm-scoped. Per-tenant policies would require a
  multi-realm settings model, which this repository does not have yet.
- Access-token validation still does not consult the session store, so a kicked
  device's access token remains valid until `exp`. Refresh tokens and session
  records are revoked immediately. Strict access-token checking is tracked in
  `session-management-architecture.md`.
