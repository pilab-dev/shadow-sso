# Client Session Management

Users need a "where am I signed in" view: every client, device, location, and
the ability to kick one device. Operators need the same for support and incident
response. And the tokens behind those sessions must be useless once a session is
kicked or a refresh token is replayed.

This document covers the session model, token/session binding, revocation,
device and location metadata, the API surface, and the anti-theft controls.

> Status: **Phase 0 implemented** (refresh keeps `sid`, refresh-token replay
> detection with family revocation, cascade revocation from the admin API).
> Phases 1–4 are design only.

## Current state

| Area | Today | Ref |
|---|---|---|
| Session model | `ID, UserID, TokenID, RefreshToken, UserAgent, IPAddress, ExpiresAt, CreatedAt, LastUsedAt, IsRevoked` | `domain/session.go:7` |
| Creation | only `completeLogin`; IP/UA are a `TODO` | `services/auth_service.go:299` |
| Token correlation | `sid` claim on access/refresh/ID tokens | `services/token_service.go:503` |
| Refresh | rotates by revoking the old refresh token | `services/oauth_service.go:340` |
| Revocation | GraphQL sets `IsRevoked` and stops there | `graphql/schema.resolvers.go:858` |
| Validation | `ValidateAccessToken` never looks at the session | `services/token_service.go:538` |

Three session-ish models coexist: `domain.Session` (`oauth_user_sessions`),
`domain.UserSession` + `UserSessionStore` (`user_sessions_oidc`), and the
login-UI cookie session in `internal/ssosession`. Pick one and collapse the rest;
this design treats `domain.Session` as the source of truth.

## Bugs fixed in Phase 0

**1. `sid` is dropped on refresh.** `RefreshToken` called
`GenerateTokenPair(..., "")`, so refreshed tokens carried no `sid`. It now uses
`GenerateTokenPairWithSession`, which keeps the session and the refresh family.

**2. Revoking a session did not revoke anything.** `RevokeSession`,
`RevokeAllSessions` and `LogoutUser` now cascade: the session is marked revoked
and `TokenRepository.RevokeTokensBySessionID` revokes every token carrying that
`sid`.

**3. Refresh replay was not detected.** Refresh tokens now carry `family`,
`parent_jti`, `used_at` and `rotated_to`. Presenting an already-used token
revokes the whole family **and** its session, logs the event, and returns
`invalid_grant`.

Remaining Phase 0 gap: validation still does not consult the session store, so a
kicked device's *access* token stays valid until it expires. That is Phase 1's
`strict` mode.

## Goals

- List a user's sessions with client, device, location, and last activity.
- Kick one device, all other devices, or everything.
- Correlate every token to a session and every session to a device.
- Detect refresh-token replay and kill the whole token family.
- Track the account lifecycle: created, refreshed, revoked, suspicious.
- Do this without a per-request database round trip on the hot path.

Non-goals: federation session sync across IdPs, precise geolocation, or
per-request behavior analytics.

## Data model

### `Session` (v2)

```go
type Session struct {
    ID        string `bson:"_id"`
    UserID    string `bson:"user_id"`
    ClientID  string `bson:"client_id"`   // which app the session belongs to
    AuthTime  time.Time `bson:"auth_time"`
    AMR       []string `bson:"amr"`       // pwd, otp, webauthn, fed:google
    ACR       string   `bson:"acr"`       // loa1, loa2 (step-up marker)

    // Device
    UserAgent string `bson:"user_agent"`
    DeviceName string `bson:"device_name"` // "Chrome on macOS"
    DeviceType string `bson:"device_type"` // desktop | mobile | tablet | cli | api
    OS         string `bson:"os"`
    Browser    string `bson:"browser"`

    // Location (coarse only)
    IPAddress  string `bson:"ip_address"`
    IPCountry  string `bson:"ip_country"`
    IPRegion   string `bson:"ip_region"`
    IPCity     string `bson:"ip_city"`
    IPASN      string `bson:"ip_asn"`

    // Lifecycle
    CreatedAt    time.Time  `bson:"created_at"`
    LastSeenAt   time.Time  `bson:"last_seen_at"`
    LastSeenIP   string     `bson:"last_seen_ip"`
    ExpiresAt    time.Time  `bson:"expires_at"`         // idle/absolute expiry
    AbsoluteEnd  time.Time  `bson:"absolute_end"`       // hard cap, never extended

    // Revocation
    IsRevoked    bool       `bson:"is_revoked"`
    RevokedAt    *time.Time `bson:"revoked_at,omitempty"`
    RevokedBy    string     `bson:"revoked_by,omitempty"`    // user id, admin id, "system"
    RevokeReason string     `bson:"revoke_reason,omitempty"`
    RevokedFrom  string     `bson:"revoked_from,omitempty"`  // session id that kicked it

    // Risk
    RiskFlags    []string   `bson:"risk_flags,omitempty"` // new_country, new_device, new_asn, reuse_detected
    Trusted      bool       `bson:"trusted"`
    BindKeyHash  string     `bson:"bind_key_hash,omitempty"` // HMAC(client, UA family), never raw
}
```

Indexes: `(user_id, is_revoked)`, `(expires_at)` TTL, `(client_id)`,
`(ip_country, created_at)` for anomaly queries.

No latitude/longitude, no street-level data. Country/region/city from an offline
GeoIP database is enough to say "Budapest, HU" and to detect a new country.

### `SessionEvent`

Append-only lifecycle log, TTL 180 days:

```go
type SessionEvent struct {
    ID        string    `bson:"_id"`
    SessionID string    `bson:"session_id"`
    UserID    string    `bson:"user_id"`
    ClientID  string    `bson:"client_id"`
    Type      string    `bson:"type"` // created|refreshed|rotated|reuse_detected|revoked|expired|risk_flagged|step_up
    IPAddress string    `bson:"ip_address"`
    Geo       string    `bson:"geo"`
    UserAgent string    `bson:"user_agent"`
    At        time.Time `bson:"at"`
    Actor     string    `bson:"actor,omitempty"`
    Reason    string    `bson:"reason,omitempty"`
    Metadata  map[string]any `bson:"metadata,omitempty"`
}
```

### Refresh token family

Rotation needs a chain so replay of any old token identifies the family:

```go
// on domain.Token, for refresh tokens
Family      string     `bson:"family"`        // random, set on first issue
ParentJTI   string     `bson:"parent_jti"`    // the token this replaced
UsedAt      *time.Time `bson:"used_at"`
RotatedTo   string     `bson:"rotated_to"`    // jti of the replacement
```

Refresh tokens are bearer secrets; store `token_hash = sha256(token)` and look up
by hash instead of keeping the raw JWT. That removes replay value from a database
dump. Dual-read during migration.

## Token ↔ session binding

Every token issued for a user session carries `sid` (session), `fam` (refresh
family, refresh tokens only), and the usual `jti`. `sid` is already emitted;
`fam` and the rotation chain are new.

```
login ──► session(sid) ──► AT(sid) + RT(sid, fam=f1, jti=r1)
                              │
refresh(r1) ──► r1 used, rotated_to=r2
                 RT(sid, fam=f1, jti=r2, parent=r1) ──► AT(sid)
```

Rules:

1. Refresh verifies the session is active **before** issuing anything.
2. Refresh keeps `sid` and `fam` (fixes Phase 0 bug 1).
3. A refresh token that is already `used_at` or `is_revoked` triggers replay
   handling: revoke every token in `fam`, revoke the session, emit
   `reuse_detected`, notify the user.
4. `sid` must exist for user grants; tokens without it are rejected by
   session-aware validation.

## Revocation semantics

`RevokeSession(ctx, id, actor, reason)` becomes a cascade:

1. mark the session revoked (`revoked_at`, `revoked_by`, `revoke_reason`);
2. revoke all tokens where `sid == id` (new repo method `RevokeBySessionID`);
3. purge cached token/session entries;
4. send back-channel logout to RPs that registered for it (`internal/oidclogout`);
5. append a `revoked` session event.

Operations and their meaning:

| Operation | Effect |
|---|---|
| `revokeSession(id)` | one device, cascade above |
| `revokeOtherSessions` | all sessions of the user except the caller's `sid` |
| `revokeAllSessions` | everything, including the caller |
| `end_session` (OIDC RP logout) | revoke the session referenced by `sid` |
| admin revoke | same cascade, `actor=admin:<id>`, reason required |
| password change | revoke all sessions except the current one |
| reuse detected | revoke the family and its session |

Enforcement mode for access tokens, per deployment:

- `strict` — validate `sid` against the session store (cached ~30s). Kick is
  effective within the cache TTL.
- `ttl` — rely on short access-token lifetimes; kick takes effect at `exp`.
  Default for high-throughput deployments.

Either way the refresh path is immediate, and since access tokens are short, the
window is bounded. A shared session-liveness cache is the mechanism that keeps
`strict` cheap.

## Device and location metadata

```go
type GeoResolver interface {
    Lookup(ctx context.Context, ip netip.Addr) (GeoInfo, error)
}

type GeoInfo struct {
    Country, Region, City, ASN string
}
```

- `MaxMindGeoResolver` reads an `.mmdb` at startup (no network per request).
- `NoopGeoResolver` is the default; location columns stay empty.
- Tests use `StaticGeoResolver`.

User-agent parsing is built in, no new dependency: a small tokenizer yields
`{DeviceName, OS, Browser, DeviceType}` and prefers `Sec-CH-UA` client hints when
present. The raw UA is retained for support and abuse analysis.

Risk flags (soft, never a hard block by default):

- `new_country` — country not seen for this user in the last 90 days;
- `new_device` — UA family not seen before;
- `new_asn` — different network provider;
- `impossible_travel` — country changed faster than flight time allows;
- `reuse_detected` — set by the refresh replay path.

Policy decides: notify only, require step-up, or force re-auth. Default for a new
country is notify + flag, not denial.

## API surface

### GraphQL (user-facing)

```graphql
type Session {
  id: ID!
  current: Boolean!
  clientId: String!
  device: Device!
  location: Location
  ipAddress: String
  authMethods: [String!]!
  createdAt: DateTime!
  lastSeenAt: DateTime!
  expiresAt: DateTime!
  risk: Risk!
  revokedAt: DateTime
  revokeReason: String
}

type Query  { mySessions: [Session!]!  sessionEvents(sessionId: ID, first: Int): [SessionEvent!]! }
type Mutation {
  revokeSession(id: ID!): Boolean!
  revokeOtherSessions: Int!
  revokeAllSessions: Int!
}
```

`current` is computed by comparing the caller's `sid` claim with `Session.ID`.
Admin variants `userSessions(userId)` / `revokeUserSession(userId, id)` sit behind
`ROLE_ADMIN`.

### Connect / gRPC

`SessionInfo` already exists in `proto/sso/v1/services.proto`; extend it with
device, location, risk, and `is_current_session`, and expose
`ListUserSessions` / `RevokeUserSession` / `RevokeAllOtherSessions`. The generated
connect client then gives `ssoctl` and the account UI the same data.

### UI

Account → Security → "Devices and sessions": current device pinned, others with
device/location/last-seen and a Kick button. Revoking the current device logs out.

## Anti-theft controls

Ordered by impact, cheapest first:

1. **Rotation with replay detection** — the single most effective control for
   stolen refresh tokens. A replayed token invalidates the family immediately.
2. **Hashed refresh tokens at rest** — a database leak no longer yields replayable
   tokens.
3. **Session-aware validation** — kicked sessions cannot mint new tokens, and in
   `strict` mode cannot use existing ones.
4. **Short access TTL + absolute session cap + idle timeout** — bounds the damage
   window regardless of detection.
5. **Soft device binding** — `bind_key_hash = HMAC(server_key, client_id | UA
   family)`; mismatch raises `new_device` risk. Do not bind IP: mobile networks
   change it. Per-client `strict_binding` can hard-fail where policy allows.
6. **Anomaly notification** — "New sign-in from Budapest, HU on Chrome" email/Slack
   for new device or country, with a one-click "revoke this session".
7. **Step-up freshness** — elevated `acr` ages out independently of the session;
   sensitive operations require a fresh `auth_time`.
8. **Sender-constrained tokens (phase 3)** — DPoP (RFC 9449): the client proves
   possession of a key, tokens carry `cnf.jkt`, refresh is bound to that key. This
   is the only control that makes a stolen token useless rather than merely
   detectable. mTLS-bound tokens are the alternative behind a service mesh.

## Migration

- Existing `oauth_user_sessions` rows are readable; new fields are `omitempty`.
  Sessions without `client_id` display as "Unknown client".
- Do not backfill location retroactively — it did not exist. Start from the first
  post-deploy session.
- Refresh tokens issued before `fam` exists get a family assigned on their next
  successful refresh.
- Collapse `UserSession` / `UserSessionStore` after the account UI moves to the
  new API; keep the login-UI cookie session (`internal/ssosession`) separate — it
  is a browser-session concern, not an OAuth one.

## Phases

| Phase | Scope | Done when |
|---|---|---|
| 0 ✅ | `sid` preserved on refresh; cascade revocation; session-aware refresh check; replay detection + family revocation | kicked device cannot refresh; replay kills the family |
| 1 | Session v2 fields, events, GraphQL + Connect list/revoke, `current` flag, `strict` validation | account UI lists and kicks devices |
| 2 | GeoIP + UA parsing, risk flags, new-device notification | new country produces an event + notification |
| 3 | Hashed refresh tokens at rest, rotation telemetry | a database dump yields no replayable token |
| 4 | DPoP / sender-constrained tokens | a stolen bearer token cannot be replayed |

## Metrics

- `sso_sessions_active{client_id}`
- `sso_session_revocations_total{reason}`
- `sso_refresh_reuse_detected_total`
- `sso_session_risk_flagged_total{flag}`
- `sso_session_duration_seconds` (histogram)

## Privacy

IP addresses and coarse location are personal data. Retention is capped by the
session-event TTL, access is limited to the user and admins with an audit trail,
and account deletion must remove session events along with the user.
