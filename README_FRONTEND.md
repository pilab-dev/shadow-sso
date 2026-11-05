# Shadow SSO - Login UI and Frontend Integration

## Who renders what

- **End-user screens** (login, MFA, consent, account chooser, account console, device verification) are rendered by
  the SSO server itself in the `api/webauth` package (embedded `html/template`s). There is nothing to build or host
  for the sign-in experience. See `docs/login-and-account-ui.md` for the full route list.
- **The Next.js app is the admin/management console only.** It talks to the backend through a BFF over
  gRPC/Connect (see `docs/cli-grpc-migration.md` and `proto/sso/v1/`); it does not take part in the OIDC login flow.
- Relying parties only need the standard OIDC endpoints (`/.well-known/openid-configuration`, `/oauth2/authorize`,
  `/oauth2/par`, `/oauth2/token`, ...).

## Login flow

1. A relying party redirects the browser to `/oauth2/authorize` (optionally with a `request_uri` from `/oauth2/par`).
2. If the user has no valid OP session, the server stores a login flow and redirects to its own `/login`.
3. `api/webauth` handles password, MFA, passkeys, social login and required actions, then `/consent` when the
   client requires it.
4. The server issues the authorization code and redirects to the relying party's `redirect_uri` (honouring
   `response_mode` `query`, `fragment`, `form_post` and `jwt`).

### Legacy `/api/oidc/*` endpoints

`GET /api/oidc/flow/{flowId}` and `POST /api/oidc/authenticate` (and `nextjs_login_url`) belong to the former
Next.js-driven login and are deprecated; new integrations must not use them. `POST /api/oidc/authenticate` is
CSRF-protected (double-submit `sso_csrf_token` cookie + `X-CSRF-Token` header/body) and rate limited.

## Session cookie

The OP session cookie (`sso_op_session`) is HTTP-only and set by the server after a successful login. If the user
returns to `/oauth2/authorize` while it is valid, the server skips the login page and issues a code directly
(subject to consent rules).

## Account chooser

The SSO keeps a Google-style **Choose an account** screen on the login page.

### Where the accounts are stored

`sso_session` is an HttpOnly, HMAC-SHA256-signed cookie. It is **not** a server
session; it contains display metadata and references:

```json
{
  "session_id": "ui-session-id",
  "accounts": [
    {
      "user_id": "...",
      "email": "user@example.com",
      "name": "Test User",
      "op_session_id": "server-side OP session id",
      "last_used": "2026-11-01T22:00:00Z"
    }
  ]
}
```

- Up to **5 accounts** are kept, most-recently-used first.
- `sso_session` contains **no passwords and no tokens**.
- `op_session_id` points to a server-side `domain.UserSession` in the
  `user_sessions_oidc` collection. Each account can have its own 24-hour OP
  session.

### How accounts are loaded

1. `GetSSOSession()` reads the `sso_session` cookie and verifies its HMAC.
2. The account list is rendered by `LoginPageHandler`.
3. Each account's `op_session_id` is checked against `UserSessionStore`:
   - **Current session** — this account owns the active `sso_op_session`.
   - **Signed in** — the account has another valid OP session and can be
     switched to without a password.
   - **Signed out** — the OP session expired or is missing; the password is
     required.
4. The last-used time is shown relative to now, for example:
   `Last used 2 hours ago`.

### Selecting an account

- **Current session** → continues without a password.
- **Signed in** → switches the active `sso_op_session` cookie to that account's
  OP session and continues without a password.
- **Signed out** → opens the password form pre-filled with that email.
- `prompt=login` always requires the password, even for the current account.
- `prompt=select_account` shows the chooser.
- **Use another account** opens the normal login form and social providers.

A successful login creates a new OP session, stores its ID in the account entry,
moves the account to the front and refreshes `last_used`.

Logout deletes **all** OP sessions listed in `sso_session`, not only the active
one, then clears both cookies.

## Server-side state adapters

Short-lived protocol state is stored behind small adapter interfaces so the backend can match the deployment:

| State | Interface | Adapters |
|---|---|---|
| Pushed authorization requests (PAR) | `domain.PARStore` | `cache/parstore` memory (ttlcache, single instance), Valkey/Redis (multi-node, `GETDEL`), `mongodb.PARStore` (TTL index, non-latency-critical but persistent) |
| Authorization codes, tokens, flows | DTS or MongoDB repositories | DTS redeems codes atomically via `ConsumeAuthCode`; Mongo via a conditional `FindOneAndUpdate` |

PAR entries are bound to the pushing client, single use, and expire after 60 seconds.

Set `require_par` on a client (gRPC `ClientManagement`) or `security_config.require_par` globally to reject authorization requests that were not pushed to `/oauth2/par` first; discovery then reports `require_pushed_authorization_requests`.

Signing keys may be RSA (RS256/384/512), RSA-PSS (PS256/384/512), ECDSA (ES256/384/512) or EdDSA. Create them with the admin `RealmService.GenerateRealmKey` RPC; they are encrypted at rest and published in the JWKS (`kty` RSA/EC/OKP). Tokens are verified against the key named by `kid`, and only with that key's algorithm.

Select the PAR backend with `par_store_backend` (`SSSO_PAR_STORE_BACKEND`): `memory` (default), `valkey` (also set `valkey_url`, e.g. `redis://host:6379/0`) or `mongodb`.

### `client_secret_jwt`

Set a client's `token_endpoint_auth_method` to `client_secret_jwt` (HS256/384/512 assertions signed with the client secret). The server must recover the raw secret, so it stores an AES-GCM sealed copy using the 32 byte config encryption key; without that key registration is rejected and the method is not advertised in discovery. Regenerate the secret after switching an existing client to this method.

### `offline_access`

Allow `offline_access` on a client's scopes to get refresh tokens with the longer `offline_refresh_token_ttl` lifetime (default 2160h); other refresh tokens keep their regular lifetime. The consent screen lists the scope. The `phone` and `address` scopes expose `phone_number`/`address` at UserInfo.

### `acr` and `amr`

ID tokens carry `amr` (RFC 8176: `pwd`, `otp`, `mfa`, `hwk`) and `acr` (`loa1` single factor, `loa2` MFA or passkey), taken from the authentication that produced the authorization code; both are stored on the session and advertised via `acr_values_supported`. `acr_values` is treated as a voluntary hint: step-up authentication is not implemented, so a request for `loa2` does not force a second factor. Logins that reuse an existing OP session do not re-assert methods and fall back to the session defaults (`pwd`, `loa1`).

### Signed request objects (JAR, RFC 9101)

`/oauth2/authorize` accepts `request=<JWT>`. The object must be signed (RS/PS 256/384/512, never `none`) with a key from the client's registered JWKS, carry `iss` = the client_id and `aud` = the issuer, and include `response_type`, `redirect_uri` etc.; only its signed values are used, unsigned query parameters do not fill gaps. Set `require_signed_request_object` on a client (gRPC `ClientManagement`) to refuse plain authorization requests (PAR remains allowed). `request_uri` still only resolves PAR-issued URIs; JWE-encrypted objects and remote `request_uri` fetching are not supported.

### Dynamic client registration management (RFC 7592)

`POST /oauth2/register` (initial access token) now also returns `registration_access_token` and `registration_client_uri`. With that token as a Bearer credential, `GET`, `PUT` and `DELETE` on `/oauth2/register/{client_id}` read, replace the metadata of (name, redirect/post-logout/logout URIs) and delete the client. Only a SHA-256 digest of the token is stored; clients created through the admin API have no token and cannot be managed this way. Any auth failure is a bare 401. The token is not rotated on update, and the client secret is only shown at creation.

### Front-channel logout

Set `frontchannel_logout_uri` (and optionally `frontchannel_logout_session_required`, which appends `iss` and `sid`) on a client via gRPC `ClientManagement`; `backchannel_logout_uri` is settable there too. `/oauth2/logout` then renders a page that loads the client's URI in a hidden iframe and continues to `post_logout_redirect_uri` through a meta refresh. Only the client named in `id_token_hint` is notified; other clients sharing the SSO session are not (yet).

### Signed UserInfo

Set `userinfo_signed_response_alg` on a client (gRPC `ClientManagement`) to receive UserInfo as an `application/jwt` response signed by the realm key (`iss` = issuer, `aud` = client_id). The value must match the algorithm of the active signing key, otherwise UserInfo answers `server_error`. Discovery lists `userinfo_signing_alg_values_supported`.

### FedCM (One Tap without an iframe)

Shadow SSO is a FedCM identity provider: the browser shows the account chooser
and no third-party cookie or iframe is needed. `/.well-known/web-identity` must be
reachable at the registrable domain root of the issuer.

```js
const cred = await navigator.credentials.get({
  identity: { providers: [{
    configURL: 'https://sso.example.com/fedcm/config.json',
    clientId: 'YOUR_CLIENT_ID',
    nonce: crypto.randomUUID(),
  }] },
});
// cred.token is an ID token; verify it with the JWKS and check the nonce.
```

The page origin must match the origin of one of the client's registered
redirect URIs. Endpoints: `/fedcm/config.json`, `/fedcm/accounts`,
`/fedcm/client_metadata`, `/fedcm/assertion`. The OP session cookie is
`SameSite=None; Secure` over HTTPS (required by browsers), and `Set-Login`
headers keep the browser's login status in sync. The token's `aud` is the client
ID; scopes are `openid` plus `email`/`profile` when the client allows them.

### CIBA (poll mode)

Client-Initiated Backchannel Authentication lets a confidential client start a
login for a known user without a browser redirect. Discovery advertises
`backchannel_authentication_endpoint` and `backchannel_token_delivery_modes_supported: ["poll"]`.

1. `POST /oauth2/ciba` with client authentication, `scope` (must include `openid`),
   `login_hint` (email or user ID) and optional `binding_message`. Returns
   `auth_req_id`, `expires_in` (300) and `interval` (5).
2. The user is notified by the webhook configured with `SSSO_CIBA_NOTIFICATION_URL`
   (and `SSSO_CIBA_NOTIFICATION_SECRET`, sent as a Bearer token). Your push service
   approves or denies through the admin gRPC `BackchannelAuthenticationService`
   (`ResolveBackchannelAuthentication`, permission `ciba:resolve`).
3. The client polls `/oauth2/token` with
   `grant_type=urn:openid:params:grant-type:ciba&auth_req_id=...`, receiving
   `authorization_pending`, `slow_down`, `expired_token`, `access_denied` or tokens.

The client needs the CIBA grant type in its allowed grant types. Ping and push
delivery modes (`client_notification_token`) are not supported.

## Rich Authorization Requests (RFC 9396)

Clients may send `authorization_details` (a JSON array of objects, each with a `type`) on `/oauth2/authorize` or
`/oauth2/par`. Only types listed in the client's `allowed_authorization_details` are accepted. The granted details
are stored on the authorization code, copied into the access token (`authorization_details` claim), returned in the
token response and introspection response, and preserved across refresh. Discovery advertises the union of
allowed types as `authorization_details_types_supported`.

## Silent Login with an Iframe

The SSO server exposes `GET /oauth2/silent-authorize` for iframe-based silent
login. It validates the client, redirect URI and PKCE exactly like
`/oauth2/authorize`, then posts either an authorization code or an OAuth error
to the parent window.

### Request

```html
<iframe
  id="sso-silent"
  src="https://sso.pilab.hu/oauth2/silent-authorize?response_type=code&client_id=my-app&redirect_uri=https%3A%2F%2Fapp.pilab.hu%2Fauth%2Fcallback&scope=openid%20profile%20email&state=RANDOM_STATE&nonce=RANDOM_NONCE&parent_origin=https%3A%2F%2Fapp.pilab.hu&code_challenge=...&code_challenge_method=S256"
  hidden
></iframe>
```

The `redirect_uri` must be an absolute `http(s)` URL on the application's
origin. `parent_origin` is optional and defaults to the redirect URI origin.
When supplied it must be an origin-only URL (no path, query or fragment). If it
does not match the redirect URI origin, the SSO page still loads so it can post
`origin_not_allowed` to the parent, but it never issues an authorization code.

### Response

The iframe posts this object to `window.parent`:

```json
{ "type": "sso-silent-result", "state": "RANDOM_STATE", "code": "..." }
```

A successful result also includes the authenticated user and `authenticated`:

```json
{
  "type": "sso-silent-result",
  "state": "RANDOM_STATE",
  "code": "...",
  "authenticated": true,
  "user": { "id": "...", "email": "...", "name": "..." }
}
```

With `mode=session` the endpoint returns the session/user without issuing an
authorization code:

```json
{
  "type": "sso-silent-result",
  "state": "RANDOM_STATE",
  "authenticated": true,
  "user": { "id": "...", "email": "...", "name": "..." }
}
```

or, when no session or consent is available:

```json
{ "type": "sso-silent-result", "state": "RANDOM_STATE", "error": "login_required" }
{ "type": "sso-silent-result", "state": "RANDOM_STATE", "error": "consent_required" }
{ "type": "sso-silent-result", "state": "RANDOM_STATE", "error": "origin_not_allowed" }
```

### Parent listener

```js
window.addEventListener("message", (event) => {
  if (event.origin !== "https://sso.pilab.hu") return;
  const data = event.data;
  if (data?.type !== "sso-silent-result" || data.state !== expectedState) return;

  if (data.error) {
    // login_required: show the normal login button
    // consent_required: start the normal top-level /oauth2/authorize flow
    return;
  }

  // Exchange data.code at /oauth2/token using the same redirect_uri
  // (and the PKCE code_verifier if one was sent).
});
```

The parent page must allow the iframe:

```html
<meta http-equiv="Content-Security-Policy" content="frame-src https://sso.pilab.hu">
```

### Notes

- The silent endpoint issues a normal authorization code. Exchange it at
  `/oauth2/token`; the code is bound to the registered `redirect_uri`.
- Always verify both `event.origin` and `event.data.state`.
- `login_required` means there is no active SSO session. `consent_required`
  means the user is logged in but must approve the client interactively.
- Cross-site iframe silent login depends on browser third-party cookie policy.
  Same-site applications (for example all under `*.pilab.hu`) work with the
  normal OP session cookie. Browsers that block third-party cookies may still
  return `login_required`.
- The silent endpoint is only frameable by the origin of the registered
  `redirect_uri`; the login, consent and MFA pages keep `frame-ancestors 'none'`.
- A browser SDK is available at
  https://github.com/pilab-cloud/shadow-sso. It performs a `HEAD`
  preflight against the silent endpoint, checks `Content-Security-Policy` and
  `X-Frame-Options`, and throws `frame_blocked` before creating the iframe when
  the response headers forbid framing. Its `mountOneTap()` widget uses
  `mode=session` for the initial account check and requests a fresh code only
  when the user clicks “Continue”.

## Important Considerations

*   **HTTPS:** All communication between your frontend and the Shadow SSO backend APIs **must** be over HTTPS.
*   **Error Handling:** Implement robust error handling for API calls to provide clear feedback to the user.
*   **Configuration:** The base URL for the Shadow SSO backend APIs will be provided to you. The redirect URL for your Next.js login page (e.g., `https://your-nextjs-sso-ui.com/login`) needs to be configured in the Shadow SSO provider.

This guide provides a foundational understanding. Specific details or advanced scenarios (like detailed 2FA interactions) should be discussed with the backend team.
