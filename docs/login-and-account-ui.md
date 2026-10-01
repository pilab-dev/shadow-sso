# Login, required actions and account console

The SSO server renders every end-user screen itself (`api/webauth`, embedded `html/template`s).
The Next.js app in `shadow-sso-frontend` is only the admin/management console.

## Routes

| Route | Purpose | Gate |
|---|---|---|
| `/login`, `/login/:provider`, `/mfa` | sign-in, social login, second factor | – |
| `/required-action` | runs the user's pending required action | flow must have finished password **and** MFA |
| `/register` | self-registration | realm `registrationAllowed` |
| `/forgot-password`, `/reset-password` | emailed reset link (30 min, single use) | realm `resetPasswordAllowed` + mail provider |
| `/verify-email` | target of the emailed verification link (24 h) | – |
| `/consent`, `/oauth2/device/verify` | OAuth consent, device-code verification | authenticated flow |
| `/account`, `/account/security`, `/account/sessions`, `/account/linked` | self-service console | signed `sso_session` cookie |

## Required actions

A user can carry `requiredActions` (`UPDATE_PASSWORD`, `CONFIGURE_TOTP`, `VERIFY_EMAIL`, …). They run in
that order after every authentication step succeeded and **before** the SSO cookie or an authorization
code is issued. Admins manage them over GraphQL:

```graphql
mutation { addRequiredAction(userId: "…", action: "CONFIGURE_TOTP") }
mutation { removeRequiredAction(userId: "…", action: "CONFIGURE_TOTP") }
mutation { setUserPassword(userId: "…", password: "tmp", temporary: true) } # forces UPDATE_PASSWORD
query { user(id: "…") { requiredActions } }
```

Actions that cannot complete in the current deployment (for example `VERIFY_EMAIL` without a mail
provider) are skipped and logged instead of trapping the user.

## Login flow state

`LoginFlowState.Pending` is `mfa` while the second factor is outstanding and `action:<ALIAS>` while a
required action is. A flow with a `UserID` but a non-empty `Pending` never yields an authorization
code (`/oauth2/authorize`, `/consent`) and never gets an SSO cookie.

## Configuration

- Mail (forgot password, email verification): set the Resend API key and from-address
  (`resend_api_key`, `from_email`). Without both, those screens report "not available".
- Public links in emails use the server's `issuer` URL.
- Realm settings: `registrationAllowed`, `resetPasswordAllowed`, `verifyEmail` (new self-registered
  users must verify their email), `displayName` (page branding), password policy.
- `SSSO_ALLOW_INSECURE_DEFAULTS=true` is for local development only; production refuses well-known
  default secrets.

## Security notes

- Reset and verification tokens are random 256-bit values; only their SHA-256 digest is stored.
- Forgot-password answers identically whether or not the account exists.
- Account changes that matter (password, MFA) require the current password or a TOTP code and are
  rate limited; a password change signs out the user's other OAuth sessions.
- Self-registration always grants `ROLE_USER` only — never the "first user is admin" bootstrap.
