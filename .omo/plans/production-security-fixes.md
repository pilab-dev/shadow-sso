# production-security-fixes - Work Plan

## TL;DR (For humans)

**What you'll get:** A production-ready SSO service with all critical security holes patched — no more unauthenticated admin API, no forgeable 2FA tokens, no hardcoded credentials in Helm charts, no bypassable WebAuthn, no predictable OTPs. Safe to deploy for Grafana and Kubernetes authentication.

**Why this approach:** 4 sequential waves ordered by severity and dependency — critical blockers first (unauthenticated GraphQL, forgeable tokens, exposed credentials), then high-impact fixes (authz, crypto, rate limiting), then hardening (injection, TLS, container), then cleanup (algorithm upgrade, dead code). Each wave is independently verifiable and deployable.

**What it will NOT do:** Not a feature addition — no new APIs, no refactoring beyond what's needed for security. Will not add SAML support, will not redesign the architecture, will not change the storage backend. Will not implement proper WebAuthn crypto (will disable it instead). Will not fix DTS auth (requires separate work).

**Effort:** Large (25+ fixes across 20+ files)
**Risk:** Medium — Helm credential changes are sensitive, GraphQL auth could break any existing tooling using GraphQL without auth
**Decisions made:**
- ✅ WebAuthn disabled for now (can be re-enabled with proper `go-webauthn` integration later)
- ✅ Plain Kubernetes Secrets for Helm now → migrate to OpenBao later
- ⏳ RS256 over HS256 chosen (migration included in Wave 4)

Your next move: Run `$start-work .omo/plans/production-security-fixes.md` to begin execution, optionally with a high-accuracy Momus review first.

---

> TL;DR (machine): 4-wave plan with Wave-0 credential rotation. 25 findings across 22 Go files + 3 Helm/Docker files. TDD for every fix. Redis-based rate limiting. RS256 JWT migration. WebAuthn disabled. ~Large effort, Medium risk.

## Scope
### Must have
- All 25 security findings from the audit fixed
- TDD for every fix (test before code)
- Each wave independently deployable
- Zero regressions in existing ConnectRPC auth patterns
- All credentials rotated after Wave 0

### Must NOT have (guardrails, anti-slop, scope boundaries)
- NO GraphQL API design changes — only auth middleware + RBAC
- NO WebAuthn crypto implementation — only disabling the broken endpoint
- NO storage backend migration (no SQL, no etcd, no Redis replacing MongoDB for persistence)
- NO new external dependencies except `go-webauthn` (if re-enabling) and `github.com/redis/go-redis/v9` (already present)
- NO new gRPC/REST endpoints
- NO Multi-realm support
- NO SAML implementation

## Verification strategy
> Agent-executed verification for all todos. Wave-level integration verification is manual (deploy + OIDC flow test).
- Test decision: **TDD** for every fix. Write failing test → verify red → implement fix → verify green.
- Framework: Go `testing` package + `stretchr/testify` assertions (already in go.mod)
- Evidence: `.omo/evidence/wave-{N}-task-{N}-production-security-fixes.log`
- Each todo must run `go test ./<affected-package>/...` and `go build ./...` as part of verification
- Final wave runs `go vet ./...` + `golangci-lint run` + full test suite
- Wave-level integration QA requires manual `deploy to test env + run full OIDC flow` (not automatable without a running cluster)

## Execution strategy
### Parallel execution waves

| Wave | Focus | Todos | Can parallelize within wave |
|-----|-------|-------|----------------------------|
| 0 | Credential rotation & prep | 3 | Cloud rotation must be manual by user; Helm cleanup in parallel |
| 1 | CRITICAL fixes | 5 | GraphQL auth + WebAuthn disable can parallel; Helm cleanup parallel |
| 2 | HIGH fixes | 8 | Rate limiting sequential; others in parallel |
| 3 | MEDIUM fixes | 8 | fully parallel |
| 4 | LOW fixes | 3 | sequential within wave |

### Dependency matrix
| Todo | Depends on | Blocks | Can parallelize with |
| --- | --- | --- | --- |
| 0 | - | 1,2,3 | all Wave 0 |
| 1-5 | 0 (creds rotated) | 6-13 | within wave 1 |
| 6-13 | 1-5 (critical path) | 14-21 | within wave 2 |
| 14-21 | wave 2 | 22-25 | within wave 3 |
| 22-25 | wave 3 | F1-F4 | within wave 4 |

## Todos
> Implementation + Test = ONE todo. Never separate.
<!-- APPEND TASK BATCHES BELOW THIS LINE WITH edit/apply_patch - never rewrite the headers above. -->
- [ ] 0. Rotate exposed MongoDB Atlas credentials and notify team
  What to do / Must NOT do: Rotate the MongoDB Atlas password for user `pirat` on `sandbox.yuwak.mongodb.net/sso_dev`. Update `.env` with new password. Commit the `.env` file password update ONLY — do NOT commit any other changes with the rotated credential. Must NOT push the old credential to any branch.
  Parallelization: Wave 0 | Blocked by: nothing | Blocks: T2 (DirectGrant fix), T5 (.env cleanup)
  References: `.env:1-2` contains `mongodb+srv://pirat:b0tZrF1rZHoJfd0X@sandbox.yuwak.mongodb.net/sso_dev`
  Acceptance criteria (agent-executable): `grep -c "pirat:" .env` = 1 (credential still present but rotated). Verify no secrets in git: `git log --all -S "b0tZrF1rZHoJfd0X" -- .env` returns empty.
  QA scenarios (agent-executable): Happy: `go build ./apps/ssso/... && go test ./mongodb/...` passes with new URI. Failure: old credential `b0tZrF1rZHoJfd0X` does not appear in any git object (`git log --all -S "b0tZrF1rZHoJfd0X"` = empty).
  Evidence: `.omo/evidence/wave-0-task-0-cred-rotation.log`
  Commit: Y | `fix(security): rotate MongoDB Atlas credentials`

- [x] 1. Add authentication middleware to GraphQL HTTP handler
  What to do / Must NOT do: In `apps/ssso/server/connectrpc_server.go` (or wherever the GraphQL handler is mounted), wrap the `graphqlHandler` with an HTTP-level auth middleware that: extracts Bearer token from `Authorization` header, validates via `TokenService.ValidateAccessToken()`, and injects `domain.TokenInfo` into `context.Context` using `domain.TokenContextKey`. This is an HTTP middleware (not a Connect interceptor) — `graphql/server.go:NewHandler` returns a plain `http.Handler`. Must NOT break the resolver_test.go. Must NOT require auth for the Apollo Sandbox `/sandbox` endpoint. Must use the same token validation logic as `middleware/auth.go:NewAuthInterceptor`. Pattern: create `graphql/auth_middleware.go` with a `func AuthMiddleware(tokenService services.TokenService, next http.Handler) http.Handler` wrapper.
  Parallelization: Wave 1 | Blocked by: 0 | Blocks: 2
  References: `graphql/server.go:49-73` (no auth), `middleware/auth.go:53-127` (existing auth pattern), `domain/context.go:8-31` (TokenContextKey), `graphql/resolver_test.go:29-178` (existing test)
  Acceptance criteria (agent-executable): `go test ./graphql/... -run TestGraphQLAuth` passes. `curl -s -o /dev/null -w "%{http_code}" -X POST -H "Content-Type: application/json" -d '{}' http://localhost:8080/graphql` returns 401 when no token provided. `curl -s -o /dev/null -w "%{http_code}" -X GET http://localhost:8080/sandbox` returns 200 (sandbox exempt).
  QA scenarios: Happy: valid JWT in Authorization header → resolver receives authenticated context. Failure: missing token → 401. Failure: expired token → 401. Evidence: `.omo/evidence/wave-1-task-1-graphql-auth.log`
  Commit: Y | `fix(security): add auth middleware to GraphQL API`

- [x] 2. Add RBAC authorization checks to all GraphQL resolvers
  What to do / Must NOT do: Add permission checks to every resolver in `graphql/schema.resolvers.go` that modifies or reads sensitive data. Use `domain.GetAuthenticatedTokenFromContext(ctx)` to get the authenticated token and check roles. Non-sensitive reads (like `realm`) may skip authz. CRITICAL: `ResetPassword`, `SetUserPassword`, `DeleteUser`, `DeleteClient`, `RevokeAllSessions`, `GenerateClientSecret`, `UpdateRealm`, `CreateUser` must require admin role (`ROLE_ADMIN`) or the specific RBAC permission from `internal/auth/rbac/rbac.go`. Must NOT modify the GraphQL schema itself — only resolver code.
  Parallelization: Wave 1 | Blocked by: 1 | Blocks: 18 (client secret plaintext)
  References: `graphql/schema.resolvers.go:361-364` (DeleteUser), `404-419` (ResetPassword), `477-480` (DeleteClient), `483-493` (GenerateClientSecret), `772-776` (RevokeAllSessions), `784-789` (UpdateRealm), `1040-1055` (SetUserPassword), `internal/auth/rbac/rbac.go:3-153`, `domain/context.go:12-18`
  Acceptance criteria (agent-executable): `go build ./graphql/...` compiles. All existing GraphQL tests pass (`go test ./graphql/...`). Each resolver's test verifies: (a) request with admin role succeeds, (b) request with user role fails with PermissionDenied, (c) request with no auth fails with Unauthenticated.
  QA scenarios: Happy: admin calls ResetPassword → success. Failure: user role calls DeleteUser → PermissionDenied. Failure: no token calls RevokeAllSessions → Unauthenticated. Evidence: `.omo/evidence/wave-1-task-2-graphql-rbac.log`
  Commit: Y | `fix(security): add RBAC authorization to GraphQL resolvers`

- [x] 3. Fix 2FA session token — use cryptographically random tokens with server-side storage
  What to do / Must NOT do: Replace `"placeholder_2fa_session_token_for_" + user.ID` in `services/auth_service.go` with a cryptographically random token generated via `crypto/rand`. Store the token server-side (in-memory TTL cache or Redis) with a 5-minute TTL. Validate Verify2FA requests against the stored token. Use the same Redis client from rate limiting (Todo 12) for multi-replica production — `helm/ssso-backend/values-production.yaml:4` sets `replicaCount: 2`, so in-memory cache WILL silently break in production (request lands on different replica). If Redis is not yet deployed, use a local TTL cache with a `FIXME` comment to switch to Redis when infra is ready. Must NOT use any deterministic or guessable value. Must NOT require database access.
  Parallelization: Wave 1 | Blocked by: 0 | Blocks: nothing
  References: `services/auth_service.go:118-135` (token generation), `services/auth_service.go:216-279` (token validation), `services/auth_service.go:220-229` (SECURITY CRITICAL comment), `internal/auth/totp/` (existing TOTP validation)
  Acceptance criteria (agent-executable): `go test ./services/... -run TestVerify2FA` passes. Generated tokens are not equal for consecutive calls on same user. Token from one user fails validation for another user. Expired token (past 5 min) fails validation. Token that never existed fails validation.
  QA scenarios: Happy: Login → get 2FA session token → Verify2FA with correct TOTP → success. Failure: forged token `"placeholder_2fa_session_token_for_X"` → 401. Failure: expired token → 401. Failure: random UUID as token → 401. Evidence: `.omo/evidence/wave-1-task-3-2fa-token.log`
  Commit: Y | `fix(security): replace placeholder 2FA session token with crypto-random tokens`

- [x] 4. Disable WebAuthn login endpoint
  What to do / Must NOT do: Change `CompleteWebAuthnLogin` in `services/auth_service.go` to immediately return an error indicating the feature is not yet implemented. Add a `"go-webauthn/webauthn"` comment noting what library to use when re-enabling. Must NOT touch the WebAuthn registration (`RegisterWebAuthnCredential`) — only the login path. Do NOT add to `publicProcedures` in `middleware/auth.go` — it's already there (line 21).
  Parallelization: Wave 1 | Blocked by: 0 | Blocks: nothing
  References: `services/auth_service.go:633-746` (CompleteWebAuthnLogin), `services/auth_service.go:684-685` (TODO comment), `middleware/auth.go:18-42` (publicProcedures), `go.mod` (no go-webauthn dependency confirmed by grepping)
  Acceptance criteria (agent-executable): `go test ./services/... -run TestWebAuthnLogin` passes with Unimplemented error. Any call to CompleteWebAuthnLogin returns error with code `CodeUnimplemented` or `CodeFailedPrecondition`. `grep -r "CompleteWebAuthnLogin" go.mod` returns empty (no accidental dependency added).
  QA scenarios: Happy: any call to CompleteWebAuthnLogin returns "not implemented" error. Failure: code must NOT issue tokens or modify state. Evidence: `.omo/evidence/wave-1-task-4-webauthn.log`
  Commit: Y | `fix(security): disable WebAuthn login until crypto verification is implemented`

- [x] 5. Remove hardcoded secrets from Helm production values
  What to do / Must NOT do: Remove `signingKeyPrivatePem` (lines 78-106), `SSSO_MONGO_URI` credential (line 67), and `initialAdmin.credentials.password` (line 12) from `helm/ssso-backend/values-production.yaml`. Replace with references to pre-created Kubernetes Secrets. Set `createSigningKeySecret: false`, `initialAdmin.createSecret: false`, remove `SSSO_MONGO_URI` value (document that it must be injected via secret). Add documentation comment explaining expected secret names and that the next migration target is **OpenBao** (`op://sso/secrets`). Must NOT delete the `values-production.yaml` file itself. Must NOT add any placeholder credentials.
  Parallelization: Wave 1 | Blocked by: 0 | Blocks: 17 (NetworkPolicy)
  References: `helm/ssso-backend/values-production.yaml:12` (admin password), `helm/ssso-backend/values-production.yaml:67` (MongoDB URI), `helm/ssso-backend/values-production.yaml:78-106` (RSA private key), `helm/ssso-backend/templates/` (deployment templates — check how secrets are referenced)
  Acceptance criteria (agent-executable): `grep -r "BEGIN.*PRIVATE KEY" helm/` returns empty. `grep -r "changeme_ssso_password" helm/` returns empty. `grep -r "PilabSSO2025" helm/` returns empty. `grep -c "ssso-signing-key" helm/ssso-backend/templates/*.yaml` > 0 (secrets still referenced, just not defined inline). `helm lint helm/ssso-backend/` passes.
  QA scenarios: Happy: `helm template helm/ssso-backend/ --values helm/ssso-backend/values-production.yaml` produces valid YAML with secret references. Failure: no inline private key or password in output. Evidence: `.omo/evidence/wave-1-task-5-helm-cleanup.log`
  Commit: Y | `fix(security): remove hardcoded secrets from Helm production values`

- [x] 6. Replace predictable OTP generation with crypto/rand
  What to do / Must NOT do: Replace `fmt.Sprintf("%06d", time.Now().UnixNano()%1000000)` in `services/user_service.go:1041` and `services/user_service.go:1070` with `crypto/rand`-based generation. Add helper function `generateSecureOTP(length int) string` in `services/user_service.go`. Must NOT use any time-based seed. Must NOT reduce OTP length (6 digits). Must change both SMS and Email OTP generation.
  Parallelization: Wave 2 | Blocked by: 0 | Blocks: nothing
  References: `services/user_service.go:1041` (SMS OTP), `services/user_service.go:1070` (Email OTP), `crypto/rand` package (available in stdlib, already imported in graphql/schema.resolvers.go:7)
  Acceptance criteria (agent-executable): `go test ./services/... -run TestOTPGeneration` passes. OTPs are not deterministic for the same timestamp. `grep -n "time.Now().UnixNano()%1000000" services/user_service.go` returns empty (both occurrences removed). All OTPs are exactly 6 digits.
  QA scenarios: Happy: calling SendSmsOtp generates a random 6-digit number. Failure: calling it twice in quick succession produces different values. Evidence: `.omo/evidence/wave-2-task-6-otp.log`
  Commit: Y | `fix(security): use crypto/rand for OTP generation instead of time-based seed`

- [x] 7. Add RBAC check to ChangePassword for admin password changes
  What to do / Must NOT do: In `services/user_service.go:354-358`, replace the "TODO - check admin privileges" comment with an actual RBAC check using `rbac.PermUsersChangePasswordAll`. The change should be: `if actingUserID != targetUserID`, then check that the authenticated user has the `ROLE_ADMIN` role or `PermUsersChangePasswordAll` permission, retrieved via `domain.GetAuthenticatedTokenFromContext(ctx)`. Return `connect.CodePermissionDenied` if the role/permission is missing. Must NOT change the self-password-change path.
  Parallelization: Wave 2 | Blocked by: 0 | Blocks: nothing
  References: `services/user_service.go:340-358` (ChangePassword logic), `internal/auth/rbac/rbac.go:18` (PermUsersChangePasswordAll), `domain/context.go:12-18` (GetAuthenticatedTokenFromContext), `middleware/authz.go:46-50` (HasPermission check pattern)
  Acceptance criteria (agent-executable): `go test ./services/... -run TestChangePasswordAuthorization` passes. Non-admin user changing another user's password gets CodePermissionDenied. Admin user changing another user's password succeeds. Self-password-change still works as before (requires old password).
  QA scenarios: Happy: admin calls ChangePassword for another user → success. Failure: user role calls ChangePassword for another user → PermissionDenied. Happy: same user changes own password with correct old password → success. Evidence: `.omo/evidence/wave-2-task-7-changepass-authz.log`
  Commit: Y | `fix(security): enforce RBAC check on admin password changes`

- [x] 8. Fix DirectGrant to use signed JWT tokens
  What to do / Must NOT do: Replace the UUID-string token generation in `services/oauth_service.go:251-269` with `s.tokenService.GenerateTokenPair()` (same as used by `completeLogin` in `services/auth_service.go:146`). Remove the manual `uuid.NewString()` calls. Remove the manual `domain.Token{}` creation and `s.tokenRepo.StoreToken()` call — `GenerateTokenPair` handles this internally. Must NOT break any existing OAuth flows.
  Parallelization: Wave 2 | Blocked by: 0 | Blocks: nothing
  References: `services/oauth_service.go:248-269` (DirectGrant), `services/auth_service.go:146` (GenerateTokenPair usage pattern), `services/token_service.go` (GenerateTokenPair signature)
  Acceptance criteria (agent-executable): `go test ./services/... -run TestDirectGrant` passes. `grep -n "uuid.NewString" services/oauth_service.go` returns zero lines in the DirectGrant function. Generated tokens are valid JWTs (parseable by `jwt.Parse()`).
  QA scenarios: Happy: DirectGrant returns a JWT access token. Failure: returned token is not a UUID string (confirmed by `jwt.Parse` succeeding). Evidence: `.omo/evidence/wave-2-task-8-directgrant.log`
  Commit: Y | `fix(security): sign DirectGrant tokens as JWTs instead of opaque UUIDs`

- [x] 9. Reject PKCE "plain" method, enforce S256
  What to do / Must NOT do: In `services/pkce_service.go:57-68`, remove the "plain" method branch (`if challenge == verifier { return true }`). Only allow S256 validation. Update `ValidatePKCEChallenge` to accept a `method` parameter, or reject at the caller. Update `PKCEConfig.SupportedMethods` to only include `["S256"]`. Must NOT break existing authorization_code flows that use S256.
  Parallelization: Wave 2 | Blocked by: 0 | Blocks: nothing
  References: `services/pkce_service.go:57-68` (ValidatePKCEChallenge), `services/oauth_service.go` (callers of PKCE validation), `apps/ssso/config/config.go:99-102` (PKCEConfig.SupportedMethods)
  Acceptance criteria (agent-executable): `go test ./services/... -run TestPKCE` passes. `grep -n "plain" services/pkce_service.go` returns empty. Authorization flows using S256 still succeed.
  QA scenarios: Happy: S256 PKCE flow succeeds. Failure: "plain" method challenge returns error. Evidence: `.omo/evidence/wave-2-task-9-pkce.log`
  Commit: Y | `fix(security): reject PKCE plain method, enforce S256 only`

- [x] 10. Mask MongoDB URI in log output
  What to do / Must NOT do: Change `mongodb/client.go:42` from `log.Info().Msgf("Initializing MongoDB client with URI: %s", uri)` to only log the host/port portion without credentials. Add a helper function `maskMongoURI(uri string) string` that strips the user:password section. Must NOT log the full connection string in any code path.
  Parallelization: Wave 2 | Blocked by: 0 | Blocks: nothing
  References: `mongodb/client.go:42` (log line), `mongodb/client.go:39-68` (InitMongoDB function)
  Acceptance criteria (agent-executable): `go test ./mongodb/...` passes. `grep -in "uri" mongodb/client.go` — manually review each match: none should print the raw URI with credentials. The masked URI does not contain `://.*:.*@` pattern (credentials embedded). Use `log.Info().Msg("Initializing MongoDB client")` without any URI param, or log `"Initializing MongoDB client — host: %s"` with only the host extracted.
  QA scenarios: Happy: log shows `"Initializing MongoDB client with URI: mongodb://***@sandbox.yuwak.mongodb.net/sso_dev"`. Failure: log contains credentials in plaintext. Evidence: `.omo/evidence/wave-2-task-10-mongodb-log.log`
  Commit: Y | `fix(security): mask MongoDB credentials in log output`

- [x] 11. Remove default config encryption key, fail on missing
  What to do / Must NOT do: Remove line `viper.SetDefault("config_encryption_key", "your-32-byte-encryption-key-here!!")` from `apps/ssso/config/config.go:176`. Add validation after config load that checks if `ConfigEncryptionKey` is still the default or empty — fail startup with clear error message. Also check `apps/ssso/ssso.go:118` for the same default. Must NOT hardcode any fallback encryption key.
  Parallelization: Wave 2 | Blocked by: 0 | Blocks: nothing
  References: `apps/ssso/config/config.go:176` (default), `apps/ssso/ssso.go:118` (possible duplicate), `apps/ssso/config/config.go:47` (ConfigEncryptionKey field)
  Acceptance criteria (agent-executable): `go build ./apps/ssso/...` succeeds. Startup without SSSO_CONFIG_ENCRYPTION_KEY set returns a clear error about missing required config. `grep -c "your-32-byte-encryption-key-here" apps/ssso/config/config.go` = 0.
  QA scenarios: Happy: server starts with valid encryption key env var. Failure: server fails to start without the key, with message "config_encryption_key is required". Evidence: `.omo/evidence/wave-2-task-11-encryption-key.log`
  Commit: Y | `fix(security): remove default encryption key, require explicit config`

- [x] 12. Implement Redis-based rate limiting on auth endpoints
  What to do / Must NOT do: Create `middleware/ratelimit.go` with a Redis-backed sliding window rate limiter. Apply to: `/oauth2/token` (10/min/IP), `/api/oidc/authenticate` (10/min/IP, 5/min/user), `Verify2FA` (3/min/user), `SendSmsOtp` (1/min/user), `SendEmailOtp` (1/min/user). Use existing Redis dependency (`github.com/redis/go-redis/v9` already in go.mod). Configuration via env vars: `SSSO_RATE_LIMIT_ENABLED=true`, `SSSO_RATE_LIMIT_REDIS_ADDR=localhost:6379`. Must NOT apply rate limiting to public discovery endpoints (`/.well-known/*`, `/healthz`, `/readyz`). Must NOT apply to already-rate-limited MFA operations in domain layer.
  **Infra note**: This creates a hard runtime dependency on Redis. The Helm chart (`helm/ssso-backend/`) does NOT include a Redis deployment template — that provisioning is OUT OF SCOPE for this plan. Before deploying Wave 2 to production, ensure Redis is available and `SSSO_RATE_LIMIT_REDIS_ADDR` is configured. For development/testing, `SSSO_RATE_LIMIT_ENABLED=false` skips rate limiting entirely. The same Redis instance should be used by Todo 3 (2FA token storage) to avoid the multi-replica trap.
  Parallelization: Wave 2 | Blocked by: nothing | Blocks: nothing
  References: `api/openidv2_1/handlers.go:1492` (TODO comment), `domain/mfa_service.go:87-90` (existing domain rate limit), `go.mod` (github.com/redis/go-redis/v9 v9.18.0), `api/openidv2_1/handlers.go:706` (TokenHandler), `api/openidv2_1/handlers.go:1432` (AuthenticateUserHandler)
  Acceptance criteria (agent-executable): `go test ./middleware/... -run TestRateLimit` passes. After 11 requests in 1 minute from same IP to `/oauth2/token`, the 11th returns 429. After 6 login attempts for same user, 6th returns 429. Rate limit headers (`X-RateLimit-Remaining`, `Retry-After`) present in response. Config disabled (SSSO_RATE_LIMIT_ENABLED=false) disables limiting.
  QA scenarios: Happy: normal requests pass through. Failure: excessive requests blocked with 429. Happy: rate limit resets after window expires. Evidence: `.omo/evidence/wave-2-task-12-rate-limit.log`
  Commit: Y | `feat(security): add Redis-based rate limiting to auth endpoints`

- [x] 13. Remove TOTP secret from API responses
  What to do / Must NOT do: In `services/two_factor_service.go:76-80`, remove the `Secret: otpKey.Secret()` line from `InitiateTOTPSetupResponse`. The QR code URI is sufficient for setup with authenticator apps. Also check `services/user_service.go:1165-1169` (SetupTotp) for the same issue. Must NOT remove the `QrCodeUri` field — that's needed for app setup.
  Parallelization: Wave 3 | Blocked by: 0 | Blocks: nothing
  References: `services/two_factor_service.go:76-80` (InitiateTOTPSetupResponse), `services/user_service.go:1165-1169` (SetupTotpResponse)
  Acceptance criteria (agent-executable): `go test ./services/... -run TestInitiateTOTPSetup` passes. `grep -n "Secret:" services/two_factor_service.go` returns only the internal storage line (line 67), not the response line (line 77 removed). QR code URI still returned in response.
  QA scenarios: Happy: InitiateTOTPSetup returns QR code URI but no raw secret. Failure: raw secret not present in response body. Evidence: `.omo/evidence/wave-3-task-13-totp-secret.log`
  Commit: Y | `fix(security): remove TOTP secret from API response`

- [x] 14. Escape special regex characters in client search
  What to do / Must NOT do: In `mongodb/client_repository.go:96-98`, wrap `filter.Search` with `regexp.QuoteMeta()` before passing to `$regex`. Add `import "regexp"`. Must NOT change any other search behavior or logic.
  Parallelization: Wave 3 | Blocked by: 0 | Blocks: nothing
  References: `mongodb/client_repository.go:94-99` (regex filter), `services/client_management_service.go:212-216` (ListClients caller)
  Acceptance criteria (agent-executable): `go test ./mongodb/... -run TestClientRepository` passes. Searching for `".*"` matches only literal `".*"` text, not all clients.
  QA scenarios: Happy: search for `"test-client"` returns expected results. Failure: search for `".*"` does NOT match all clients. Evidence: `.omo/evidence/wave-3-task-14-regex-escape.log`
  Commit: Y | `fix(security): escape regex special characters in client search`

- [x] 15. Default LDAP TLS verification to required
  What to do / Must NOT do: In the LDAP provider, change the default for `skipTLSVerify` to `false` (or default TLS verification to `true`). If InsecureSkipVerify is set to true in configuration, log a warning. Must NOT remove the option to skip TLS — just change the default. Must NOT affect non-LDAP connections.
  Parallelization: Wave 3 | Blocked by: 0 | Blocks: nothing
  References: `internal/federation/ldap_provider.go:238` (InsecureSkipVerify), internal/federation/ directory
  Acceptance criteria (agent-executable): `grep -n "InsecureSkipVerify" internal/federation/ldap_provider.go` shows the value defaults to `false` when not specified. If `ldap_tls_skip_verify=true` is set, connection proceeds with warning.
  QA scenarios: Happy: no config set → TLS verification enabled. Failure: TLS verification explicitly disabled → warning log but connection proceeds. Evidence: `.omo/evidence/wave-3-task-15-ldap-tls.log`
  Commit: Y | `fix(security): default LDAP TLS verification to required`

- [x] 16. Pin Docker base image version
  What to do / Must NOT do: Change `FROM alpine:latest` in `Dockerfile:26` to `FROM alpine:3.21` (or the latest stable version). Must NOT use `latest` tag or any mutable tag. Must NOT change the builder stage image (`FROM golang:1.25-alpine`).
  Parallelization: Wave 3 | Blocked by: 0 | Blocks: nothing
  References: `Dockerfile:26` (alpine:latest), `Dockerfile:2` (golang:1.25-alpine)
  Acceptance criteria (agent-executable): `grep -n "alpine:latest" Dockerfile` returns empty. `grep -n "alpine:" Dockerfile` shows a pinned version like `alpine:3.21`. `make docker-build` succeeds.
  QA scenarios: Happy: docker build succeeds with pinned version. Failure: "latest" tag not used. Evidence: `.omo/evidence/wave-3-task-16-docker-pin.log`
  Commit: Y | `fix(security): pin Alpine base image version in Dockerfile`

- [x] 17. Add Kubernetes NetworkPolicy to Helm chart
  What to do / Must NOT do: Create `helm/ssso-backend/templates/networkpolicy.yaml` with a NetworkPolicy that: (a) allows ingress on port 8080 from Ingress controller (label `app.kubernetes.io/component: ingress-controller`), (b) allows egress to MongoDB (via label or CIDR), (c) allows internal DNS (port 53 UDP), (d) denies all other ingress/egress. Set `networkPolicy.enabled: true` in values-production.yaml. Must NOT block health check probes.
  Parallelization: Wave 3 | Blocked by: 5 (Helm cleanup) | Blocks: nothing
  References: `helm/ssso-backend/values-production.yaml`, `helm/ssso-backend/templates/`, Kubernetes NetworkPolicy API: networking.k8s.io/v1
  Acceptance criteria (agent-executable): `helm lint helm/ssso-backend/` passes. `helm template helm/ssso-backend/ --values helm/ssso-backend/values-production.yaml` includes a NetworkPolicy resource. `kubectl apply --dry-run=client -f` on the generated YAML succeeds.
  QA scenarios: Happy: NetworkPolicy is created with correct pod selector matching app labels. Failure: NetworkPolicy blocks health check probes (port 8080 still accessible from kubelet). Evidence: `.omo/evidence/wave-3-task-17-netpol.log`
  Commit: Y | `feat(security): add Kubernetes NetworkPolicy to Helm chart`

- [x] 18. Hash client secrets in GraphQL GenerateClientSecret
  What to do / Must NOT do: In `graphql/schema.resolvers.go:483-494`, after generating the random secret with `generateRandomSecret()`, hash it using the resolver's `PasswordHasher` before storing. Return the unhashed secret in the response (user needs to see it once). Mirror the pattern from `client_management_service.go:150-157` (which properly hashes). Must NOT break the existing client_management_service hashing path.
  Parallelization: Wave 3 | Blocked by: 2 (GraphQL RBAC) | Blocks: nothing
  References: `graphql/schema.resolvers.go:483-494` (GenerateClientSecret), `services/client_management_service.go:150-157` (proper hashing pattern), `graphql/schema.resolvers.go:30` (PasswordHasher field in Resolver struct)
  Acceptance criteria (agent-executable): `go test ./graphql/... -run TestGenerateClientSecret` passes. `grep -n "client.Secret = secret" graphql/schema.resolvers.go` is replaced with hashing. Secret returned in response is the original (unhashed), stored value is hashed.
  QA scenarios: Happy: client secret generated → returned in response → stored hash in DB verified by `passwordHasher.Verify(storedHash, returnedSecret)` works. Failure: stored value equals returned secret (no hashing) → test fails. Evidence: `.omo/evidence/wave-3-task-18-client-secret.log`
  Commit: Y | `fix(security): hash client secrets in GraphQL GenerateClientSecret`

- [x] 19. Validate scope intersection in Token Exchange
  What to do / Must NOT do: In `services/oauth_service.go:620-624`, when `scope` is provided, validate that it is a subset of the original token's scope (`tokenInfo.Scope`). Compute the intersection of requested scope and original scope. Use the intersection (not the raw request) for the new token. Must NOT allow scope escalation beyond the original token's permissions.
  Parallelization: Wave 3 | Blocked by: 0 | Blocks: nothing
  References: `services/oauth_service.go:596-625` (TokenExchange), `services/token_service.go` (GenerateTokenPair signature)
  Acceptance criteria (agent-executable): `go test ./services/... -run TestTokenExchange` passes. Token exchange with subset scope succeeds with the requested scope. Token exchange with superset scope returns only the intersection. Token exchange without scope uses original token's scope.
  QA scenarios: Happy: original token has "openid profile", request "openid" → new token has "openid". Failure: original token has "openid", request "openid admin" → new token has "openid" only. Evidence: `.omo/evidence/wave-3-task-19-scope-intersect.log`
  Commit: Y | `fix(security): validate scope intersection in Token Exchange`

- [x] 20. Restrict WebSocket CheckOrigin to configured origins
  What to do / Must NOT do: Replace `CheckOrigin: func(r *http.Request) bool { return true }` in `graphql/server.go:58-60` with a configurable origin check. Add a `AllowedOrigins` field to the GraphQL config (or read from environment). Accept requests where `Origin` header matches an allowed origin or is empty (same-origin requests). When in development mode, allow all origins (configurable). Must NOT accept arbitrary origins in production.
  Parallelization: Wave 3 | Blocked by: 0 | Blocks: nothing
  References: `graphql/server.go:56-64` (WebSocket transport), `graphql/server.go:49-74` (NewHandler signature)
  Acceptance criteria (agent-executable): `go test ./graphql/... -run TestWebSocketOrigin` passes. Request with `Origin: https://evil.com` is rejected (when auth is bypassed or when reached directly). Request with `Origin: https://sso.pilab.hu` is accepted. Request with no `Origin` header is accepted.
  QA scenarios: Happy: allowed origin connects to WebSocket. Failure: disallowed origin gets 403. Evidence: `.omo/evidence/wave-3-task-20-websocket-origin.log`
  Commit: Y | `fix(security): restrict GraphQL WebSocket CheckOrigin to allowed origins`

- [x] 21. Implement CSRF protection in AuthenticateUserHandler
  What to do / Must NOT do: Implement the commented-out CSRF check in `api/openidv2_1/handlers.go:1441-1447`. Use the existing flow cookie (HttpOnly, SameSite) as a CSRF token. Compare a header value (e.g., `X-CSRF-Token`) against the flow cookie value. Generate a random CSRF token during flow creation (`api/openidv2_1/handlers.go:502-528` — where `flowID` is created and `StoreFlow` is called) and set it as a separate cookie. Check that the header matches the cookie on authenticate requests. Must NOT use the flow ID directly as the CSRF token (it's already used for flow lookup). Must NOT block legitimate requests from the Next.js frontend.
  Parallelization: Wave 3 | Blocked by: 0 | Blocks: nothing
  References: `api/openidv2_1/handlers.go:1441-1447` (TODO comment), `api/openidv2_1/handlers.go:502-528` (flow creation with StoreFlow + cookie set), `api/openidv2_1/handlers.go:1378-1395` (GetFlowDetailsHandler — reads flow cookie)
  Acceptance criteria (agent-executable): `go test ./api/openidv2_1/... -run TestCSRF` passes. Request without CSRF header returns 403. Request with mismatched CSRF header returns 403. Request with matching CSRF header succeeds.
  QA scenarios: Happy: authenticate request with valid CSRF header succeeds. Failure: missing CSRF header → 403. Failure: wrong CSRF header → 403. Evidence: `.omo/evidence/wave-3-task-21-csrf.log`
  Commit: Y | `fix(security): implement CSRF protection in AuthenticateUserHandler`

- [x] 22. Migrate JWT signing from HS256 to RS256
  What to do / Must NOT do: Add `AddRSAKeySigner` method to `TokenSigner` in `services/signer.go` that uses `jwt.SigningMethodRS256` with an RSA private key loaded from the configured path (`SSSO_SIGNING_KEY_PATH`). Load the PEM file, parse with `jwt.ParseRSAPrivateKeyFromPEM`. Use the existing `pkg/crypto/keys.go:GenerateRSAKey()` for key generation if no key exists. Update `TokenService` initialization to use RSA by default. Keep HS256 as fallback for backward compatibility during migration. Must NOT break existing JWT validation — add a validation path that tries RS256 first, then falls back to HS256 for tokens signed before migration.
  Parallelization: Wave 4 | Blocked by: 0 | Blocks: nothing
  References: `services/signer.go:27-38` (HS256), `services/token_service.go` (token validation), `pkg/crypto/keys.go:10-12` (GenerateRSAKey), `apps/ssso/config/config.go:18` (SigningKeyPath), `apps/ssso/config/config.go:50` (TokenSigningKey). Use `github.com/golang-jwt/jwt/v5` (already in go.mod)
  Acceptance criteria (agent-executable): `go test ./services/... -run TestJWTAlgorithm` passes. New tokens are signed with RS256 (`jwt.Parse` with `WithMethods{jwt.SigningMethodRS256}` succeeds). Old tokens signed with HS256 still validate (fallback). `jwt.ParseRSAPrivateKeyFromPEM([]byte(keyPEM))` succeeds on the loaded key.
  QA scenarios: Happy: new token validates with RS256. Happy: old HS256 token still validates. Failure: token signed with different key fails validation. Evidence: `.omo/evidence/wave-4-task-22-jwt-rs256.log`
  Commit: Y | `feat(security): migrate JWT signing from HS256 to RS256`

- [x] 23. Remove authorization codes from log output
  What to do / Must NOT do: Remove or redact authorization code values from log statements. Change `log.Info().Str("code", code).Msg("Authorization code generated and saved")` in `services/oauth_service.go:469` to log only the user ID and client ID, NOT the code itself. Check `mongodb/auth_code_repository.go:48` for the same issue. Must NOT change log levels (keep Info debug-level appropriate).
  Parallelization: Wave 4 | Blocked by: 0 | Blocks: nothing
  References: `services/oauth_service.go:469` (auth code log), `mongodb/auth_code_repository.go:48` (auth code repo log)
  Acceptance criteria (agent-executable): `grep -rn 'Str("code"' services/oauth_service.go` returns empty. `grep -rn '"code"' mongodb/auth_code_repository.go` returns empty. Auth code flow still works.
  QA scenarios: Happy: auth code generated → log shows user ID and client ID only. Failure: log does not contain the raw auth code value. Evidence: `.omo/evidence/wave-4-task-23-authcode-log.log`
  Commit: Y | `fix(security): remove authorization codes from log output`

- [x] 24. Remove dead code with hardcoded JWT secret
  What to do / Must NOT do: Remove the `ParseClaims` function in `api/openidv2_1/middleware.go:22-49` that uses `[]byte("your-256-bit-secret")`. Confirm via `codegraph_callers` or grep that no caller exists. If any caller exists, update it to use `tokenService.ValidateAccessToken()`. Must NOT remove the `UserAuthMiddleware` or `AdminAuthMiddleware` which use the correct token validation path.
  Parallelization: Wave 4 | Blocked by: 0 | Blocks: nothing
  References: `api/openidv2_1/middleware.go:22-49` (ParseClaims), `api/openidv2_1/middleware.go:71-123` (UserAuthMiddleware/AdminAuthMiddleware)
  Acceptance criteria (agent-executable): `grep -rn "ParseClaims" --include="*.go" .` returns only the definition line(s) or empty (function removed). `go build ./api/openidv2_1/...` succeeds.
  QA scenarios: Happy: `ParseClaims` function is removed. Failure: remaining caller of `ParseClaims` would break the build. Evidence: `.omo/evidence/wave-4-task-24-deadcode.log`
  Commit: Y | `chore(security): remove dead ParseClaims function with hardcoded JWT secret`

- [x] 25. Wire RSA signing key correctly in server config
  What to do / Must NOT do: Update `apps/ssso/ssso.go` and `apps/ssso/config/config.go` to properly wire the RSA signing key. When `SSSO_SIGNING_KEY_PATH` is set, load the PEM file, parse the RSA private key, and configure `TokenSigner` for RS256. Fall back to HS256 if no key path is set (for development). Add startup log that indicates which signing algorithm is active. Must NOT require a signing key path for development mode. Must NOT fall back to hardcoded defaults.
  Parallelization: Wave 4 | Blocked by: 22 | Blocks: nothing
  References: `apps/ssso/config/config.go:18` (SigningKeyPath), `apps/ssso/config/config.go:50-51` (TokenSigningKey/TokenSigningKeyFile), `apps/ssso/ssso.go` (server startup), `services/signer.go` (AddKeySigner)
  Acceptance criteria (agent-executable): `go build ./apps/ssso/...` succeeds. With `SSSO_SIGNING_KEY_PATH` set, server starts and logs "Using RS256 signing". Without it, starts with "Using HS256 signing (development mode)".
  QA scenarios: Happy: RS256 tokens validated correctly. Happy: dev mode HS256 tokens work locally. Failure: wrong key path returns startup error. Evidence: `.omo/evidence/wave-4-task-25-signing-key.log`
  Commit: Y | `feat(security): wire RSA signing key configuration for RS256 JWT`

## Final verification wave
> Runs in parallel after ALL todos. ALL must APPROVE. Surface results and wait for the user's explicit okay before declaring complete.
- [ ] F1. Plan compliance audit — verify every todo's acceptance criteria is met
- [ ] F2. Code quality review — run `golangci-lint run`, `go vet ./...`, check no new lint warnings
- [ ] F3. Integration QA — deploy to test environment, run full OIDC flow: `curl POST /oauth2/token` with client_credentials; `curl POST /oauth2/token` with authorization_code; `curl POST /oauth2/introspect`; `curl POST /oauth2/revoke`; `curl -X POST /graphql` with Bearer token; rate limit trigger (11 requests → 429). All return expected HTTP status codes and well-formed JSON bodies. This step requires a live environment — agent marks as complete only when all curl commands return correct output.
- [ ] F4. Scope fidelity — confirm no unintended changes outside scope (grep for new external dependencies, changed public interfaces)

## Commit strategy
- **Per-todo atomic commits** — each todo is one commit
- **Conventional commits**: `fix(security):`, `feat(security):`, `chore(security):`
- **No force-push** to shared branches
- **Branch naming**: `security/production-hardening`
- **No squash** — each commit independently reviewable
- **Final branch PR**: squash-merge to `main` with all commits preserved

## Rollback strategy per wave

| Wave | Rollback action |
|------|----------------|
| **0** | Rotate credentials back (or notify DB admin to reinstate old credentials) |
| **1** | `git revert` commits Wave-1 (GraphQL auth, 2FA token, WebAuthn, Helm) on a revert branch → deploy revert. GraphQL reverts to unauthenticated state (worse security, but functional). 2FA returns to placeholder (functional with same security level). Helm returns to inline secrets (explicitly less secure). |
| **2** | `git revert` Wave-2 commits individually. OTP reverts to time-based (less secure, same functionality). ChangePassword reverts to no-RBAC (pre-exploit-mitigation state). DirectGrant reverts to UUIDs (worse security, gRPC clients still work). PKCE reverts to plain-method acceptance (more permissive). Rate limiting reverts to unlimited (worse security). No persistent data migration needed — all changes are code-only. |
| **3** | `git revert` Wave-3 commits. All changes are code-only (no data migrations). TOTP secret re-exposed in API (regression on F13). No production data impact — revert is safe. |
| **4** | `git revert` Wave-4 commits. JWT reverts to HS256 — existing RS256 tokens WILL fail validation if rolled back. **Wave 4 rollback hazard**: If Wave 4 is deployed and RS256 tokens are issued, rolling back to HS256 will break all RS256 tokens until they expire. To safely roll back Wave 4: (a) configure validation to accept BOTH HS256 and RS256, (b) wait for RS256 token TTL to expire, (c) then revert to HS256-only. |

**General rule**: Waves 1-3 are safe to revert (code-only, no data format changes). Wave 4 (RS256) requires a grace period for token expiry before full reversion.

## Success criteria
1. All 25 findings from the security audit are addressed
2. No regressions in the OIDC flows (login, token, introspect, revoke, device)
3. All GraphQL operations require authentication and authorization
4. No hardcoded credentials anywhere in the codebase or Helm charts
5. Rate limiting blocks brute-force attacks on auth endpoints
6. All cryptographic operations use standard library or well-audited packages (not time-based seeds)
7. JWT tokens use RS256 asymmetric signing
8. All tests pass: `go test ./...`
