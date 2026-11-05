# Client Credentials: Audience, Subject and Groups

`client_credentials` tokens are now usable as Kubernetes OIDC bearer tokens. Three
changes make that possible:

| Claim | Before | Now |
|---|---|---|
| `aud` | always the requesting `client_id` | the requested RFC 8707 `audience`/`resource`, defaulting to `client_id` |
| `sub` | empty (no user) | the client identity (`client_id`, e.g. the service account email) |
| `groups` | not emitted | `service_account_groups`, falling back to `service_account_roles` |

The actor/origin claims (`roles`, `realm_access`, `resource_access`) are unchanged.

## Requesting an audience

Send either the `audience` or the RFC 8707 `resource` parameter, repeated or
space/comma separated:

```sh
curl -s https://sso.pilab.hu/oauth2/token \
  -d grant_type=client_credentials \
  -d client_id=sa-1234@pilab.iam.sso.dev \
  -d client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer \
  -d client_assertion="$SIGNED_JWT" \
  -d audience=kubernetes
```

Multiple values are allowed (`aud` becomes a JSON array). When no audience is
requested, `aud` remains `[client_id]`, so existing integrations are unaffected.

## Provisioning

A client may only request audiences listed in `allowed_audiences`; its own
`client_id` is always permitted. This prevents a service account from minting a
token for a resource it was not provisioned for.

```json
{
  "client_id": "sa-1234@pilab.iam.sso.dev",
  "allowed_grant_types": ["client_credentials"],
  "token_endpoint_auth_method": "private_key_jwt",
  "allowed_scopes": ["openid"],
  "allowed_audiences": ["kubernetes"],
  "service_account_roles": ["k8s-view"],
  "service_account_groups": ["sso:k8s-view", "sso:k8s-devs"]
}
```

- `allowed_audiences` — whitelist for `aud` requests (empty = self only).
- `service_account_groups` — the `groups` claim. When empty, `service_account_roles`
  is reused so a single list can drive both claims.
- `auth/audience` requests outside the whitelist fail with `invalid_target`.

## Emitted token example

```json
{
  "iss": "https://sso.pilab.hu",
  "sub": "sa-1234@pilab.iam.sso.dev",
  "aud": ["kubernetes"],
  "exp": 1762265400,
  "iat": 1762261800,
  "jti": "…",
  "roles": ["k8s-view"],
  "groups": ["sso:k8s-view", "sso:k8s-devs"]
}
```

## Kubernetes configuration

kube-apiserver:

```
--oidc-issuer-url=https://sso.pilab.hu
--oidc-client-id=kubernetes
--oidc-username-claim=sub
--oidc-username-prefix=sso:
--oidc-groups-claim=groups
--oidc-groups-prefix=sso:
```

RBAC binds the groups, so authorization stays in the cluster:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: sso-k8s-view
subjects:
  - kind: Group
    name: sso:k8s-view
roleRef:
  kind: ClusterRole
  name: view
  apiGroup: rbac.authorization.k8s.io
```

An exec credential plugin then requests `audience=kubernetes` and hands the token
to kubectl; see the credential-helper design for that side.

## Notes

- Tokens are bearer credentials. kube-apiserver does not introspect them, so
  their lifetime (`exp`) is the revocation control. Keep TTLs short for
  privileged groups.
- `sub` is the client ID, not a user. Kubernetes usernames will look like
  `sso:sa-1234@pilab.iam.sso.dev`.
- The token endpoint now avoids validating the client twice. This also fixes
  `client_credentials` with `private_key_jwt`, which previously failed because
  there is no client secret to re-validate.
