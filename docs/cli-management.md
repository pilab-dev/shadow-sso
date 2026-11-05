# CLI management guide

`ssoctl` is the only management surface for Shadow SSO. This guide covers the
full-coverage commands, the interactive wizard, dynamic completion and silent
provisioning.

## Coverage guarantee

Every management feature is reachable from the CLI in one of three ways:

1. **Bespoke command** — the ergonomic path (`user`, `mfa`, `client`, `role`,
   `group`, `realm`, …).
2. **Any Connect RPC** — `ssoctl api call`.
3. **Any GraphQL operation** — `ssoctl graphql query|mutate`.

If a bespoke command is missing, the feature is still fully manageable through
(2) or (3). `ssoctl api services` is the authoritative list of every RPC the
binary knows about.

```bash
# Discover all RPCs
ssoctl api services

# Discover the GraphQL schema
ssoctl graphql introspect

# Print a request template for any RPC
ssoctl api describe UserService/UpdateUser

# Call it (literal JSON, @file, or stdin)
ssoctl api call UserService/UpdateUser --data '{"user_id":"...","first_name":"Ada"}'
ssoctl api call ClientManagementService/RegisterClient --data @client.json
echo '{"user_id":"..."}' | ssoctl api call UserService/GetUser --data -

# GraphQL
ssoctl graphql query 'query { realm { realm displayName } }'
ssoctl graphql mutate 'mutation($id: ID!) { deleteRole(id: $id) }' --variable id=abc
ssoctl graphql mutate --file ./fix.graphql --variables '{"input":{...}}'
```

## Interactive wizard

`client register` launches a survey-style TUI (bubbletea) when required flags are
missing:

```bash
ssoctl client register
ssoctl client register --wizard          # force it even with flags
```

The wizard collects name, description, type, redirect URIs, post-logout URIs,
grant types, scopes, token endpoint auth method, consent and contacts, then shows
a review screen. `shift+tab`/`esc` goes back, `ctrl+c` cancels.

Flags prefill the wizard, so a partial command is a valid starting point:

```bash
ssoctl client register --name "My App" --type public
```

## Silent / non-interactive provisioning

Pass `--no-interactive` (or set `SSOCTL_NO_INTERACTIVE=1`, or run without a TTY).
No prompt or TUI is ever shown; missing required parameters produce an error that
names the exact flags:

```bash
$ ssoctl client register --no-interactive
client registration requires the following parameters in non-interactive mode: [--name --type]
```

This is the mode to use in CI, Ansible, Terraform provisioners and cron jobs.

## Dynamic completion

Completion queries the server, so it reflects the current state of the realm.
Client IDs are completed for `client get|update|delete`, user IDs for user/MFA
commands, IdP IDs for `idp`, and mapper IDs for `token-mapper`.

```bash
# bash
source <(ssoctl completion bash)
# zsh
source <(ssoctl completion zsh)
# fish
ssoctl completion fish | source
```

Each completion entry carries the human-readable name as its description. If the
server is unreachable, completion silently falls back to file completion.

## Command map

| Domain | Commands |
|---|---|
| Users | `user register/get/list/update/delete/activate/lock/set-password/change-password/verify-email/execute-actions`, `user failed-attempts`, `user email`, `user phone`, `user password-reset`, `user login-otp` |
| User credentials | `user mfa-method`, `user webauthn`, `user totp`, `user attribute` |
| MFA | `mfa status/reset/require/list/disable`, `mfa totp enroll`, `mfa hotp enroll`, `mfa email enroll`, `mfa push`, `mfa challenge`, `mfa recovery generate`, `mfa passkey`, `mfa policy` |
| Clients | `client register/get/list/update/delete`, `client generate-secret`, `client generate-keys` |
| Roles | `role list/get/create/update/delete/assign-user/unassign-user/assign-group/unassign-group/mappings/composite` |
| Groups | `group list/get/create/update/delete/members/add-member/remove-member` |
| Realm | `realm show/update`, `realm-key list/update`, `mfa policy` |
| Sessions | `session list/clear/revoke/revoke-all/logout-user` |
| Auth flows | `auth-flow list/get/create/update/delete/set-executions` |
| Client scopes | `client-scope create/get/list/update/delete` |
| Protocol mappers | `protocol-mapper create/get/list/update/delete` |
| OIDC discovery | `oidc-config get/update` |
| Identity providers | `idp add/get/list/update/delete` |
| Federation | `federation list/remove` |
| Service accounts | `service-account create-key/list-keys/delete-key` |
| Attributes / mappers | `user attribute …`, `token-mapper …` |
| Audit | `audit list` |
| Everything else | `api call …`, `graphql query|mutate …` |

## Notes and limits

- TOTP is the only second factor the web login page can verify. Email, push and
  HOTP commands exist for completeness and self-service, but those factors do not
  satisfy the browser login yet.
- Passkeys can be listed and removed (`mfa passkey`, `user webauthn`), but WebAuthn
  registration/assertion ceremonies are not implemented server-side.
- `api call` and `graphql` require an authenticated context (`ssoctl auth login`)
  for anything that is not public.
