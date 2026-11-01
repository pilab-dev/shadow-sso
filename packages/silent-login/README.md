# @pilab/shadow-sso-silent-login

Iframe-based silent login for Shadow SSO. It loads the SSO silent-authorize
endpoint in a hidden iframe, waits for a `postMessage`, and returns an
authorization code or a typed error.

The library has no runtime dependencies and ships ESM, CJS and TypeScript
declarations.

## Install

```bash
pnpm add @pilab/shadow-sso-silent-login
```

## Usage

```ts
import {
  generatePkcePair,
  isSilentLoginError,
  silentLogin,
} from "@pilab/shadow-sso-silent-login";

const pkce = await generatePkcePair();
sessionStorage.setItem("sso_pkce_verifier", pkce.verifier);

try {
  const { code, state } = await silentLogin({
    issuer: "https://sso.pilab.hu",
    clientId: "my-app",
    redirectUri: "https://app.pilab.hu/auth/callback",
    scope: "openid profile email",
    codeChallenge: pkce.challenge,
    codeChallengeMethod: "S256",
    timeoutMs: 8000,
  });

  // Exchange `code` at /oauth2/token. For a public SPA, send the stored
  // code_verifier as well. A backend/BFF can do the exchange instead.
  console.log("silent login code", code, state);
} catch (error) {
  if (isSilentLoginError(error)) {
    switch (error.code) {
      case "login_required":
        // No active SSO session: show the normal login button.
        break;
      case "consent_required":
        // Start the normal top-level /oauth2/authorize flow.
        break;
      case "origin_not_allowed":
        // This application origin is not allowed for the client's redirect URI.
        break;
      default:
        // timeout, frame_error, server_error, aborted, invalid_config, ...
        break;
    }
  }
}
```

## Options

| Option | Required | Description |
| --- | --- | --- |
| `issuer` | yes | SSO base URL, for example `https://sso.pilab.hu` |
| `clientId` | yes | OAuth client ID |
| `redirectUri` | yes | Registered redirect URI on the application origin |
| `scope` | no | Defaults to `openid profile email` |
| `state` | no | Generated when omitted; returned on success |
| `nonce` | no | OIDC nonce |
| `codeChallenge` | no | PKCE challenge; use `generatePkcePair()` |
| `codeChallengeMethod` | no | `S256` (default) or `plain` |
| `parentOrigin` | no | Defaults to `window.location.origin`; in the browser it must match the page origin |
| `preflight` | no | Check the SSO frame policy headers before creating the iframe; defaults to `true` |
| `timeoutMs` | no | Defaults to `10000` |
| `extraParams` | no | Additional query parameters; critical parameters cannot be overridden |
| `iframeTitle` | no | Accessible iframe title |
| `signal` | no | `AbortSignal` for cancellation |

## Error codes

- `login_required` — no active SSO session
- `consent_required` — the user is logged in but must approve the client
- `origin_not_allowed` — the parent origin differs from the registered redirect URI origin
- `access_denied`, `invalid_request`, `invalid_client`, `invalid_scope`
- `server_error`
- `timeout` — the iframe did not answer; commonly CSP/XFO blocking, third-party cookie blocking, or network failure
- `frame_blocked` — the preflight found `X-Frame-Options` or `frame-ancestors` that blocks the parent origin
- `frame_error` — the iframe failed to load
- `aborted` — the supplied `AbortSignal` was aborted
- `not_browser` — Web Crypto or a browser environment is unavailable
- `invalid_config` — invalid issuer, redirect URI, parent origin or timeout

## Frame-policy preflight

Before inserting the iframe, the library sends a `HEAD` request to the
silent-authorize URL and reads these response headers:

- `Content-Security-Policy` (`frame-ancestors`)
- `X-Frame-Options`

If the headers block the parent origin, the library logs a `console.error` and
throws:

```ts
SilentLoginError { code: "frame_blocked" }
```

This catches proxy/CDN misconfigurations before the iframe is created. The SSO
must expose those headers through CORS:

```
Access-Control-Expose-Headers: Content-Security-Policy, X-Frame-Options
```

The Shadow SSO silent endpoint does this automatically for the matching
`parent_origin`.

If the preflight request fails (network, CORS, or an older SSO that returns
404/405), the library logs a `console.warn` and continues with the iframe. The
normal `timeout` path still applies if the browser then blocks the iframe.

Set `preflight: false` to skip this check.

## How the origin check works

The SSO silent endpoint accepts a `parent_origin` query parameter. If that
origin does not match the origin of the registered `redirect_uri`, the SSO page
still loads (so it can answer) but it posts `origin_not_allowed` and never
issues an authorization code. This is why an invalid origin gets a proper
error instead of a silent timeout.

If the browser itself refuses to load the iframe (for example because the SSO
page is not frameable at all), no JavaScript inside it can post a message. In
that case the library rejects with `timeout`; the error message mentions
CSP/X-Frame-Options and third-party cookie policy.

## Parent page requirements

The application page must allow the SSO origin in its own CSP:

```html
<meta
  http-equiv="Content-Security-Policy"
  content="frame-src https://sso.pilab.hu"
/>
```

The `redirectUri` and the page hosting the library must be on the same origin.
A backend-only redirect URI on a different origin will be reported as
`origin_not_allowed`.

## Browser caveats

- Same-site applications (for example `app.pilab.hu` and `sso.pilab.hu`) work
  with the normal OP session cookie.
- Cross-site iframe silent login depends on the browser's third-party cookie
  policy. Browsers that block third-party cookies will return
  `login_required`, or occasionally `timeout` if the iframe itself is blocked.
- Silent login is not a replacement for the interactive OIDC flow. Use it to
  check for an existing session, then fall back to the normal
  `/oauth2/authorize` redirect when it fails.

## Development

```bash
pnpm install
pnpm test
pnpm typecheck
pnpm build
```

`tsup` emits `dist/index.mjs`, `dist/index.cjs` and `dist/index.d.ts`.
