# MFA management

Operator tooling for diagnosing and controlling second factors. This exists because
a user can be locked out by a second factor they did not knowingly configure, and
because MFA can now be enforced per user or per realm.

## Diagnose first

```bash
ssoctl mfa status user@example.com
```

The status output lists every source that can trigger a second factor:

| Source | Meaning |
|---|---|
| `is_two_factor_enabled` | Legacy aggregate flag, set by any TOTP/email/push enable path |
| `two_factor_method` | `TOTP`, `EMAIL`, `PUSH`, `HOTP`, or `NONE` |
| `email_mfa_enabled` / `push_mfa_enabled` | Method-specific flags |
| `mfa_methods[].verified` | Explicit method records |
| `webauthn_devices` | Registered passkeys (not usable at login yet) |
| browser auth flow | A `REQUIRED` non-password execution forces every user |

**Important:** the server-rendered `/mfa` page only verifies TOTP. If the effective
trigger is `EMAIL` or `PUSH` and no TOTP secret exists, the code prompt can never
succeed. `mfa status` reports this explicitly in its warnings list.

## Commands

```bash
# Read the full diagnosis (trigger, flags, recovery codes, warnings)
ssoctl mfa status <user>

# Clear everything: flags, TOTP secret, recovery codes, methods
ssoctl mfa reset <user> [--remove-passkeys] [--yes]

# Force (or stop forcing) a second factor for one user
ssoctl mfa require <user> [--off]

# Enroll TOTP for a user (prints QR + secret, then verifies a code)
ssoctl mfa totp enroll <user> [--code 123456]

# Issue a new set of recovery codes (invalidates old ones)
ssoctl mfa recovery generate <user>

# List methods and passkeys / remove a passkey
ssoctl mfa list <user>
ssoctl mfa passkey list <user>
ssoctl mfa passkey remove <user> --device <device-id>

# Realm-wide enforcement
ssoctl mfa policy show
ssoctl mfa policy set --require-mfa=true
```

`<user>` accepts either the user ID or the email address.

Self-service equivalents remain under `ssoctl user 2fa ...` (setup, verify,
disable, recovery-codes). Those operate on the authenticated caller and require
re-authentication to disable.

## Enforcement behavior

MFA is required when **any** of these is true:

- the user has `mfa_required`,
- the realm has `require_mfa`,
- the active browser flow has a `REQUIRED` non-password execution.

At password login:

1. If the account has a usable TOTP factor, `/mfa` asks for the code.
2. If MFA is required and no factor is configured (including an abandoned
   pending secret), the user is redirected to `/mfa/enroll`.
3. If the account has an **active** factor the web page cannot verify (email,
   push, HOTP, flag without secret), login is refused with an explanatory page.
   It is deliberately not downgraded to enrollment. An administrator must run
   `mfa reset` first.

The RPC login path (`AuthService.Login`, used by `ssoctl auth login` and API
clients) applies the per-user and realm policies too. A required account with
no usable TOTP factor gets `FailedPrecondition`; enroll it first with
`ssoctl mfa totp enroll <user>`. A required account with TOTP gets the normal
`two_factor_session_token` challenge. The browser-flow enforcement is
web-only, since the RPC path does not evaluate authentication flows.

Naming only one factor is not enough: the enrollment completion endpoint is gated
by a one-shot `mfa_enrollment_verified` marker on the login flow, so a session
that only passed the password step cannot skip an existing second factor.

## What reset does and does not do

`mfa reset` clears:

- `is_two_factor_enabled`, `two_factor_method`, `two_factor_secret`
- `two_factor_recovery_codes`
- `email_mfa_enabled`, `push_mfa_enabled`, push device tokens and challenges
- `mfa_methods`
- WebAuthn devices, only with `--remove-passkeys`

It does **not** clear `mfa_required`. A reset account that is still required will
be sent to enrollment at its next login. Clear it with `mfa require <user> --off`
if the requirement itself is wrong.

## API surface

Administrative RPCs on `sso.v1.TwoFactorService`:

| RPC | Permission |
|---|---|
| `GetMFAStatus` | self, or `2fa:manage_others` |
| `ResetUserMFA` | `2fa:manage_others` |
| `SetUserMFARequired` | `2fa:manage_others` |
| `GenerateRecoveryCodes` (with `user_id`) | self, or `2fa:manage_others` |
| `InitiateTOTPSetup` / `VerifyAndEnableTOTP` (with `user_id`) | self, or `2fa:manage_others` |
| `GetMFAPolicy` | any authenticated principal |
| `SetMFAPolicy` | `2fa:manage_others` |

## Limitations

- Passkeys are not a usable second factor yet: the login page does not implement
  the WebAuthn assertion ceremony. Devices can be listed and removed, but they do
  not satisfy MFA.
- Enforcement applies to new logins. Existing OP sessions remain valid until they
  expire; that mirrors normal SSO session semantics.
- The GraphQL `resetUserTwoFactor` mutation is now admin-only and also clears the
  stored TOTP secret and recovery codes.
