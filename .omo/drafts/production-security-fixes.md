# Draft: production-security-fixes

## Status
awaiting-approval

## Pending Action
write `.omo/plans/production-security-fixes.md`

## Overview
Fix 25 security findings (8 CRITICAL, 7 HIGH, 8 MEDIUM, 2 LOW) from the full security audit of shadow-sso before production deployment for Grafana and Kubernetes authentication.

## Topology (Components)

| ID | Component | Outcome | Status | Evidence |
|----|-----------|---------|--------|----------|
| C1 | GraphQL API auth | Add auth middleware + RBAC checks to all resolvers | Pending | graphql/server.go:49-73, graphql/schema.resolvers.go |
| C2 | 2FA session token | Replace placeholder with server-side random tokens | Pending | services/auth_service.go:124, 220-229 |
| C3 | WebAuthn verification | Add proper crypto verification or disable | Pending | services/auth_service.go:684-685 |
| C4 | OTP generation | Switch from time-based to crypto/rand | Pending | services/user_service.go:1041, 1070 |
| C5 | ChangePassword authz | Add RBAC check for admin changes | Pending | services/user_service.go:340-358 |
| C6 | DirectGrant tokens | Use signed JWTs instead of UUIDs | Pending | services/oauth_service.go:251-269 |
| C7 | PKCE plain method | Reject plain method, enforce S256 | Pending | services/pkce_service.go:57-68 |
| C8 | MongoDB URI logging | Mask credentials in log | Pending | mongodb/client.go:42 |
| C9 | Default encryption key | Remove default, fail on missing | Pending | apps/ssso/config/config.go:176 |
| C10 | Helm credentials | Remove hardcoded RSA key, creds, admin pass | Pending | helm/ssso-backend/values-production.yaml |
| C11 | .env credentials | Rotate exposed credentials | Pending | .env:1-3 |
| C12 | Rate limiting | Implement Redis-based rate limit on auth endpoints | Pending | api/openidv2_1/handlers.go:1492 |
| C13 | TOTP secret exposure | Remove Secret from response | Pending | services/two_factor_service.go:76-80 |
| C14 | MongoDB regex injection | Escape search terms | Pending | mongodb/client_repository.go:96-98 |
| C15 | LDAP TLS verification | Default to requiring TLS | Pending | internal/federation/ldap_provider.go:238 |
| C16 | Docker base image | Pin alpine:latest version | Pending | Dockerfile:26 |
| C17 | NetworkPolicy | Add to Helm chart | Pending | helm/ssso-backend/templates/ |
| C18 | Client secret plaintext | Hash in GraphQL GenerateClientSecret | Pending | graphql/schema.resolvers.go:483-494 |
| C19 | Token exchange scope | Validate scope intersection | Pending | services/oauth_service.go:620-624 |
| C20 | WebSocket CheckOrigin | Restrict to configured origins | Pending | graphql/server.go:58-60 |
| C21 | JWT signing algorithm | Switch from HS256 to RS256 | Pending | services/signer.go:27-38 |
| C22 | Auth code logging | Remove auth code from logs | Pending | services/oauth_service.go:469 |
| C23 | Token signing key config | Wire RSA key properly | Pending | services/signer.go + apps/ssso/config/config.go |
| C24 | CSRF protection | Implement in AuthenticateUserHandler | Pending | api/openidv2_1/handlers.go:1441-1447 |
| C25 | ParseClaims dead code | Remove hardcoded secret function or secure it | Pending | api/openidv2_1/middleware.go:28 |

## Decisions

### Implementation Order
The fixes will be done in order of severity and dependency:
1. **Wave 1 (CRITICAL - no auth required)**: GraphQL auth (C1), 2FA token (C2), WebAuthn (C3), Helm cleanup (C10), .env rotate (C11)
2. **Wave 2 (HIGH)**: OTP generation (C4), ChangePassword authz (C5), DirectGrant (C6), PKCE (C7), URI logging (C8), encryption key (C9), rate limiting (C12)
3. **Wave 3 (MEDIUM)**: All medium findings (C13-C20, C24)
4. **Wave 4 (LOW/cleanup)**: JWT algorithm (C21), auth code logging (C22), signing key config (C23), dead code (C25)

### Test Strategy
TDD for all fixes — write failing test first, then fix, then verify green.

### Auth Approach for GraphQL
Use the existing `middleware.NewAuthInterceptor`-style pattern adapted for GraphQL middleware: extract Bearer token from Authorization header, validate via `TokenService.ValidateAccessToken()`, inject `domain.TokenInfo` into context using `domain.TokenContextKey`. Apply `AroundOperations` on the gqlgen handler.

### Rate Limiting Approach
Use Redis (already a dependency) with per-IP + per-user sliding window. Create a `middleware/ratelimit.go` interceptor. Default: 10 req/min per IP, 5 req/min per user for login, 3 req/min per user for 2FA.

### Encryption Key Approach
Remove default value. Make `config_encryption_key` required. Fail startup if not set. Document env var `SSSO_CONFIG_ENCRYPTION_KEY`.

### Helm Secret Management Approach
Remove all hardcoded secrets from `values-production.yaml`. Add `secrets:` block that references External Secrets Operator or HashiCorp Vault. Document rotation procedure.

### WebAuthn Approach
Disable the endpoint by returning an error ("not implemented") until proper `go-webauthn` integration is done. This is safer than shipping broken crypto.

### JWT Signing Approach
Implement RS256 signing path using the existing RSA key generation (`pkg/crypto/keys.go`). Add a `AddRSAKeySigner` method to `TokenSigner`. The `SSSO_SIGNING_KEY_PATH` config value will load the RSA PEM file.

## Open Questions (None - all resolved via exploration)

All forks were resolved by codebase evidence. No user decisions needed beyond approval of the approach.
