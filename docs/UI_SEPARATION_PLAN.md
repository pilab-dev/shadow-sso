# UI separation plan (Keycloak model)

## Goal

Split the user interface into two independent parts, the way Keycloak does:

| Keycloak | Shadow SSO | Lives in | Audience |
|---|---|---|---|
| Login theme (login, register, reset credentials, required actions, consent, device) | **Login UI** | `shadow-sso/api/webauth` (server-rendered Go templates) | everybody authenticating |
| Account console (`/realms/x/account`) | **Account UI** | `shadow-sso/api/webauth` (`/account/*`) | the signed-in end user |
| Admin console (`/admin`) | **Management console** | `shadow-sso-frontend` (Next.js + PatternFly) | administrators |

Rule: **anything an end user sees belongs to the SSO server**. The frontend is an ordinary
OIDC relying party (`admin-ui` client) that only calls the GraphQL management API.
The management console never renders a password, MFA or consent form.

## Current state (verified in code)

Already in the backend:

- Login, social login, account picker, merge, MFA challenge, consent, device verify (`api/webauth/*`, 9 templates).
- Session cookie `sso_session` (`internal/ssosession`), CSRF cookie, `RateLimiter`, `validReturnTo` (`api/webauth/security.go`).
- Pluggable authentication flows (`internal/authflow`, `AuthenticationFlowRepository`).
- Full `TwoFactorService`: TOTP, HOTP, email OTP, push, recovery codes (`services/interfaces.go:89`).
- Password-reset token storage + `SendPasswordResetEmail` (`domain/user.go:121`, `domain/repositories.go:50,129`).
- Realm flags `RegistrationAllowed`, `ResetPasswordAllowed` (`domain/keycloak_types.go`), password policies in `user_service.go`.
- GraphQL `setUserPassword(..., temporary)`, which is the seed of "required actions".

Missing (the real work):

- No end-user UI for: register, forgot/reset password, change password, MFA enrolment, sessions, linked accounts, granted apps.
- No `RequiredActions` concept on the user.
- No verify-email flow, no step-up re-authentication for sensitive account changes.

Frontend leftovers: `src/app/login/{mfa,select-mfa,push-approval}` are **empty directories**;
`/consent` + `components/consent-screen.tsx` and `/profile` are end-user UI that duplicate
(or will duplicate) the backend. `/login` (redirect), `/callback`, `/logout`, `/api/health` stay.

## Target architecture

```
Browser ── /login, /register, /reset, /consent, /oauth2/device/verify ──▶ SSO (Login UI)
Browser ── /account/*  (cookie session, CSRF) ───────────────────────────▶ SSO (Account UI)
Browser ── admin console ──OIDC code+PKCE (client admin-ui)──▶ SSO ──▶ GraphQL /graphql (role: admin)
```

- **Account UI auth:** the existing `sso_session` cookie (same-origin, signed). No second OIDC client; simpler than Keycloak's SPA+REST account console and enough for a server-rendered UI.
- **Step-up:** sensitive actions (change password, add/remove MFA, delete sessions of others) require a fresh authentication (`auth_time` < N minutes, configurable), otherwise redirect to `/login?return_to=…&prompt=login`.
- **Required actions** run inside the login flow after credentials/MFA and before the authorization code is issued, exactly like Keycloak.
- **Theming:** one `base.html`; realm display name + logo + accent colour read from `RealmSettings`; `AccountURL` exposed in discovery-adjacent config so the management console can link to it.

## Phases

### Phase 0 — Frontend cleanup (½ day, no backend change)
1. Delete empty `src/app/login/{mfa,select-mfa,push-approval}`.
2. Delete `src/app/consent`, `src/components/consent-screen.tsx`, `src/app/profile` (backend `consent.html` is authoritative). Remove the now-unused `authServiceClient` consent calls and generated proto usages if nothing else needs them.
3. Update `src/proxy.ts` public-path list (drop `/consent`).
4. Admin masthead user menu: "Manage account" → `${SSO_URL}/account`; "Sign out" stays RP-initiated logout.
5. Move the WebAuthn / MFA items from frontend `MISSING_FEATURES.md` to backend docs.

**Done when:** `next build` has only `/admin/*`, `/login`, `/callback`, `/logout`, `/api/health`.

### Phase 1 — Required actions engine (backend, foundation) — DONE on `feat/required-actions`

Delivered: `User.RequiredActions`, `authflow.NextRequiredAction`, a single login completion point
(`WebAuth.finishLogin`), `/required-action` with an `UPDATE_PASSWORD` handler, GraphQL
`addRequiredAction` / `removeRequiredAction` / `User.requiredActions`, and `setUserPassword(temporary)` now
flags `UPDATE_PASSWORD`. `sendRequiredActionsEmail` moves to Phase 2 (it shares the reset-token work).
It also fixed a security hole: a password-only login that still needed MFA left `flow.UserID` set, and
`/oauth2/authorize?flow_id=` issued a code anyway. Flows now carry `Pending` (`mfa` / `action:<alias>`) and
nothing is issued, and no SSO cookie is set, until it is clear. Not covered yet: the social-login callback
(`openidv2_1/handlers.go` federation path) and the JSON login endpoint do not run required actions.

- `domain.User.RequiredActions []string` + repo support; constants: `UPDATE_PASSWORD`, `CONFIGURE_TOTP`, `VERIFY_EMAIL`, `UPDATE_PROFILE`, `TERMS_AND_CONDITIONS`.
- `RequiredActionHandler` interface in `internal/authflow` (`Applies(user)`, `Render`, `Submit`) with a registry; the runner consults it after the last auth step.
- Map existing `setUserPassword(temporary=true)` → adds `UPDATE_PASSWORD`.
- GraphQL: `addRequiredAction`, `removeRequiredAction`, `sendRequiredActionsEmail(userId, actions, lifespan)` (Keycloak's *execute actions email*), backed by the existing reset-token storage generalised to action tokens.
- Realm-level default required actions for new users.

**Done when:** a user flagged `UPDATE_PASSWORD` cannot obtain a code without changing the password; unit tests in `authflow`.

### Phase 2 — Login-side screens — DONE on `feat/login-screens` (except Terms / Update profile)

Delivered: `/forgot-password` + `/reset-password` (digest-only token storage, anti-enumeration, realm
`ResetPasswordAllowed`), `CONFIGURE_TOTP` (QR, verify, one-time recovery codes), `VERIFY_EMAIL`
(+ `/verify-email` link), `/register` (realm `RegistrationAllowed`, new `RealmSettings.VerifyEmail`,
never grants admin). Mail-dependent screens are only enabled when a Resend key and from-address are
configured. Follow-ups: expose `verifyEmail` in the GraphQL realm settings, sendRequiredActionsEmail,
revoke other sessions after a password change.

Order by value:
1. **Update password** (required action) — reuses password policy + hasher; invalidates other sessions on success.
2. **Forgot / reset password** (`/reset-credentials`, `/reset-credentials/confirm`) gated by `ResetPasswordAllowed`; single-use hashed token, constant-time response (no user enumeration), rate limited.
3. **Configure TOTP** (required action + reused by account UI): QR (`InitiateTOTPSetup`), verify, show recovery codes once (`VerifyAndEnableTOTP`).
4. **Verify email** (required action): signed token mail link.
5. **Register** (`/register`) gated by `RegistrationAllowed`; honours realm password policy, optional verify-email.
6. Terms and Update profile (small, optional).

Every handler: CSRF, rate limit, `return_to` validation, generic errors, audit event (`AuditService`).

### Phase 3 — Account UI (`/account`) — DONE on `feat/account-ui` (except "Applications")

Delivered: `/account` (profile), `/account/security` (password change, TOTP enrol/disable, new recovery codes),
`/account/sessions` (list + revoke, ownership-checked), `/account/linked` (list + unlink, never removes the last
sign-in method), sign-out. Auth = signed `sso_session` cookie; sensitive changes need the current password
(or a TOTP code) via a rate-limited step-up check; a password change revokes the user's other OAuth sessions.
Not done: "Applications" (granted consents) needs a consent store that does not exist yet (consent is
currently asked per authorization, never persisted); linking *new* social accounts from the console.

Sections mirroring Keycloak's account console, all server-rendered:

| Page | Backing service |
|---|---|
| Personal info (name, email, attributes) | `UserService`, `UserAttributeService`, realm user-profile config |
| Signing in: password, TOTP/email/push, recovery codes, (later) passkeys | `TwoFactorService`, `pkg/auth` |
| Device activity: list/revoke sessions | `SessionRepository` |
| Linked accounts: link/unlink social IdPs | `FederationService.ListUserFederatedIdentities` |
| Applications: granted consents, revoke | consent store (new `ListUserConsents`/`RevokeConsent`) |

Cross-cutting: step-up check middleware, flash messages, account-level audit trail.

### Phase 4 — Hardening and integration — DONE on `feat/hardening` and `feat/passkeys`

Delivered: passkeys (registration + username-less login, signed-cookie challenge state, replay and clone
guards, verified against a software authenticator in tests), realm `displayName` branding, a full
password → MFA → required action → authorize chain test, CSP fix (QR `data:` images), docs
(`login-and-account-ui.md`). Remaining: browser-level E2E (Playwright against a real stack) and
Terms / Update-profile required actions.

- Passkeys/WebAuthn in the Login UI + Account UI with **persistent** challenge storage (Mongo/DTS, not in memory) and a token-issuing path; drop the "WebAuthn without tokens" workaround.
- Realm theming settings (display name, logo, colour) consumed by `base.html`.
- Playwright (or Go `httptest`) E2E: register → verify email → login → required MFA → consent; reset-password flow; account password change with step-up.
- Docs: `docs/` login/account pages, admin docs for required actions and emails.

## Cross-cutting decisions to confirm

1. **Account UI auth** via the SSO cookie (recommended) vs a separate `account-console` OIDC client + REST API like Keycloak.
2. **Registration default:** off unless `RegistrationAllowed` is set per realm (recommended).
3. **Email OTP / email links** require a configured mail provider; without one the screens must degrade to an explicit "not available" page, never a silent success.
4. **i18n:** start English-only, but route every string through a template function so a message bundle can be added later.
5. Keep templates plain `html/template` (no second JS build in the SSO).

## Risks

- Account-takeover surface: reset tokens, step-up, session invalidation after password change; each needs tests, not just happy paths.
- Required actions inside `authflow.Runner` touch the core login path (`api/webauth/login.go` currently has uncommitted changes) — land Phase 1 on a clean branch.
- Frontend deletions are safe today (nothing imports them), but keep the redirect for `/profile` → `${SSO_URL}/account` for bookmarks.
