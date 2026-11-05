# Roadmap

Gaps versus Keycloak, ordered by priority. SAML is out of scope. Single realm by design.
Each item lists the main areas of work and what must be true before it is advertised in discovery.

Rule: never advertise a capability in `/.well-known/openid-configuration` before it is implemented and tested.

## Phase 0 — Correctness and security debt (do first)

| # | Item | Notes |
|---|------|-------|
| 0.1 | `private_key_jwt` verification | `domain/client_auth.go` verifies assertions with the server's realm key. Must verify with the client's registered public key (client JWKS or `jwks_uri`), enforce `iss=sub=client_id`, `aud` (token endpoint or issuer), `exp`, and single-use `jti`. |
| 0.2 | DTS parity | Persist the nonce on auth codes, session and family fields on tokens; fix `GetAuthCode` NotFound detection for connect errors. |
| 0.3 | PAR backend switch | Add a config key selecting ttlcache / Valkey / Mongo for `PARStore`; add miniredis and Mongo adapter tests. |
| 0.4 | RFC 9207 on errors | Add `iss` to authorization error responses, then set `authorization_response_iss_parameter_supported=true`. |

## Phase 1 — Client authentication and tokens

| # | Item | Notes |
|---|------|-------|
| 1.1 | `client_secret_basic` at the token endpoint | Already accepted at introspection and revocation; add to token and PAR, then advertise. |
| 1.2 | `client_secret_jwt` | HS256/384/512 assertions keyed by the client secret; same claim checks as 0.1. |
| 1.3 | Asymmetric signing algorithms | Key types: EC (ES256/384/512), RSA-PSS (PS256), EdDSA. Extend `RealmKey.Type`, `TokenSigner`, JWKS (`kty`, `crv`, `x`, `y`), per-client `id_token_signed_response_alg`. Then advertise accurate `id_token_signing_alg_values_supported`. |
| 1.4 | `offline_access` scope | Long-lived offline refresh tokens, consent prompt, revocation, separate lifetime settings. |
| 1.5 | `address` and `phone` scopes | User attributes, claim mapping, UserInfo and ID token claims. |
| 1.6 | ACR / AMR | Emit `acr` and `amr` from the authentication flow (password, otp, webauthn); `acr_values` request parameter; `acr_values_supported`; step-up via `claims` parameter. |
| 1.7 | Token exchange (RFC 8693) | Grant `urn:ietf:params:oauth:grant-type:token-exchange`: impersonation and delegation, audience restriction, per-client permission policy. |

## Phase 2 — Request and response handling

| # | Item | Notes |
|---|------|-------|
| 2.1 | Request objects (JAR, RFC 9101) | Parse `request` and `request_uri`; verify signature against client keys; `request_object_signing_alg_values_supported`; optional `require_signed_request_object`. Optional JWE later (see 4.1). |
| 2.2 | `require_pushed_authorization_requests` | Per-client and global switch; reject non-PAR authorization requests. |
| 2.3 | Implicit and hybrid flows | `id_token`, `id_token token`, `code id_token`, `code token`, `code id_token token`; `c_hash`/`at_hash`; fragment responses. Low priority (deprecated in OAuth 2.1). |
| 2.4 | JWT bearer grant (RFC 7523) | Assertion grant for service-to-service use. |
| 2.5 | Pairwise subjects | `sector_identifier_uri`, per-client salt, `subject_type` client setting. |

## Phase 3 — Sessions, logout and registration

| # | Item | Notes |
|---|------|-------|
| 3.1 | Front-channel logout | Per-client `frontchannel_logout_uri` and session-required flag; render logout iframes in the end-session page. |
| 3.2 | OIDC Session Management | `check_session_iframe` endpoint and `session_state`. Consider skipping in favour of 3.1 plus back-channel. |
| 3.3 | Dynamic client registration management (RFC 7592) | `registration_access_token`, `registration_client_uri`, GET/PUT/DELETE; initial access tokens; registration policies. |
| 3.4 | CIBA | `/oauth2/ciba`, poll/ping/push modes, user-approval channel, `backchannel_*` discovery metadata. |

## Phase 4 — Advanced security

| # | Item | Notes |
|---|------|-------|
| 4.1 | Encryption (JWE) | ID token, UserInfo and request-object encryption; client encryption keys from JWKS; `*_encryption_alg/enc_values_supported`. |
| 4.2 | Signed UserInfo | `userinfo_signed_response_alg`, `application/jwt` response. |
| 4.3 | mTLS (RFC 8705) | `tls_client_auth` and `self_signed_tls_client_auth`; certificate-bound access tokens (`cnf.x5t#S256`); `mtls_endpoint_aliases`. |
| 4.4 | UMA 2.0 / authorization services | Resource server, resources, scopes, policies, permission tickets, RPT. Large; only if a concrete need appears. |

## Phase 5 — Platform and admin features

All admin features must also be exposed over gRPC for the BFF.

| # | Item | Notes |
|---|------|-------|
| 5.1 | User federation | LDAP first (bind, sync, read-only and writable modes, mappers); Kerberos later. Builds on the existing federation provider interface. |
| 5.2 | Identity brokering depth | More provider types (generic OIDC, Microsoft, Apple, GitHub, Google exist), first-login flows, account linking, token storage, mappers. |
| 5.3 | Fine-grained admin permissions | Resource-scoped permissions (per client, group, role) replacing the coarse `Perm*` set; admin-role delegation. |
| 5.4 | Client policies and profiles | Conditions and executors (e.g. enforce PKCE, require PAR, restrict algorithms, FAPI profiles). |
| 5.5 | Event listeners / extension points | Pluggable event sinks (webhook, Kafka/NATS), an event stream API beyond the audit log. |
| 5.6 | Localisation | `ui_locales`, `locale` claim handling, message bundles for `api/webauth` pages and emails. |
| 5.7 | Themes | Per-client branding for `api/webauth` login pages. |
| 5.8 | Client-scope evaluation tooling | "Evaluate" endpoint: given client and user, show effective scopes, mappers and the resulting token. |

## Suggested order

1. Phase 0 in full (security debt first).
2. 1.1, 1.3, 2.2 (cheap, high interoperability value), then 1.2.
3. 1.4–1.6 and 2.1.
4. 3.1, 3.3, 5.1–5.3.
5. Everything else on demand.

## Definition of done per item

- Implementation behind existing interfaces, config switch where behaviour changes defaults.
- Unit tests plus an integration test through the HTTP handler.
- Discovery updated only when the feature works; golden file regenerated (`UPDATE_GOLDEN=1`).
- gRPC admin surface and RBAC permissions for anything configurable.
- `README_FRONTEND.md` and `CHANGELOG.md` updated.
