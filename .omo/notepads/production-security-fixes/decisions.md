# production-security-fixes - Decisions

- WebAuthn disabled for now (can be re-enabled with go-webauthn later)
- Plain Kubernetes Secrets for Helm now → migrate to OpenBao later
- RS256 over HS256 chosen (migration in Wave 4)
- TDD for every fix
