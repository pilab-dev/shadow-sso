# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Self-registration with email, full name, phone, email confirmation link, duplicate/federated-email handling, and MFA readiness.
- Login flow with pluggable MFA: email OTP, HOTP, TOTP, SMS and passkeys (`port.MFAProvider`, `MFARegistry`).
- Password recovery and password change flows.
- OAuth 2.0 / OIDC core endpoints plus device code, silent authorize, PAR (RFC 9126), RAR (RFC 9396) and JARM (`response_mode=jwt`).
- Pluggable identity source seam (`internal/identity`, `internal/directory`) so directory services (PiRectory/LDAP) can own identity and passwords.
- Externalized `port.TemplateLoader` with `SHADOW_SSO_TEMPLATE_DIR` override and reload support.
- HTML email templates with Resend and SMTP/PiMail transports (`SMTP_HOST` takes precedence over Resend).
- Multi-account sessions with an account chooser.
- `apps/sssoctl` CLI client.
- One Tap / silent login server endpoints, compatible with the official `@pilab/shadow-sso` JS/TS SDK.
- Backend session management (list, revoke, events) for MongoDB and DTS.
- External certificate/key store port (`port.KeyStore`) with MongoDB-backed RSA/EC/DSA implementation.

### Changed

- Web portal routes moved from `openid_config.go` into `api/webauth/routes.go`.
- GoReleaser config migrated to v2.

### Fixed

- Consent page no longer truncates when rendering string scopes; RAR `authorization_details` render correctly.
- JARM no longer silently downgrades to query mode when signing is unavailable.

### Security

- Strong (non-UUID) email validation tokens (32 random bytes, SHA-256 digest stored).

## [0.1.0] - YYYY-MM-DD

### Added
- Initial release.
