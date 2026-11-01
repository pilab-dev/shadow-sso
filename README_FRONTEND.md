# Shadow SSO - Frontend Integration Guide (OIDC Separate UI Flow)

This document outlines how a frontend application (e.g., a Next.js UI) acting as the authentication interface for the Shadow SSO OpenID Connect (OIDC) Provider should interact with the backend.

## Overview

In this flow, when a Relying Party (RP) initiates an OIDC login, if the user is not already authenticated with the Shadow SSO provider, the provider will redirect the user's browser to your frontend application. Your frontend will then handle the user authentication process (e.g., display login forms, manage 2FA) and communicate back to the Shadow SSO backend to complete the OIDC flow.

## Authentication Flow Steps

1.  **Initial Redirect from OIDC Provider to Frontend UI:**
    *   The Shadow SSO backend's `/oauth2/authorize` endpoint will redirect the user to your configured Next.js login page.
    *   A `flowId` query parameter will be appended to this URL. This ID is crucial for linking the frontend authentication back to the original OIDC request.
    *   Example Redirect URL: `https://your-nextjs-sso-ui.com/login?flowId=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`
    *   **(Optional CSRF)** The OIDC provider *may* also set a CSRF cookie (e.g., `sso_csrf_token`) at this stage. Your frontend should persist this cookie.

2.  **Frontend Retrieves Flow Details:**
    *   Your frontend application should extract the `flowId` from the URL query parameters.
    *   Make a `GET` request to the Shadow SSO backend to fetch details about the OIDC authorization request:
        *   **Endpoint:** `GET /api/oidc/flow/{flowId}`
            *   Replace `{flowId}` with the actual ID.
        *   **Expected Response (JSON):**
            ```json
            {
                "client_id": "some_relying_party_client_id",
                "client_name": "Name of the Relying Party Application", // To display to the user
                "scope": "openid profile email", // Scopes requested by the RP
                "original_params": { // Original OIDC parameters, useful for context
                    "response_type": "code",
                    "redirect_uri": "https://rp.example.com/callback",
                    "state": "client_state_value",
                    "nonce": "client_nonce_value"
                    // ... and other parameters like code_challenge, code_challenge_method
                }
                // Potentially other details to help the UI display context,
                // e.g., if consent is required, specific claims requested.
            }
            ```
    *   Use the `client_name` and `scope` to inform the user which application is requesting access and what permissions are being sought.

3.  **User Authentication on Frontend:**
    *   Display your login form (username/password).
    *   Handle any multi-factor authentication (2FA/MFA) steps if required by your policies. This guide primarily focuses on the initial credential submission. Advanced 2FA flows might involve additional API calls not detailed here.

    ### Logging in with Social Providers (e.g., Google, Facebook, GitHub)

    As an alternative or addition to the traditional email/password login, your frontend can offer users the option to log in using their existing accounts with social identity providers.

    **User Experience:**

    1.  On your login page, alongside the email/password form, display buttons such as "Login with Google", "Login with Facebook", or "Login with GitHub".
    2.  When the user clicks one of these buttons, your frontend application should redirect the user's browser to a specific endpoint on the Shadow SSO backend that initiates the chosen social login. This endpoint will typically include the `flowId` and the identifier of the chosen social provider.
        *   Example initiation URL (actual URL pattern to be confirmed with backend team):
            `https://your-sso-backend.com/api/oidc/federate/{provider}?flowId=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`
            (Where `{provider}` could be `google`, `facebook`, `github`, etc.)
    3.  The Shadow SSO backend will then redirect the user to the respective social provider's authentication page (e.g., Google's login page).
    4.  The user authenticates with the social provider (e.g., enters Google credentials).
    5.  Upon successful authentication with the social provider, the user is redirected back to a callback endpoint on the Shadow SSO backend.
    6.  The Shadow SSO backend processes the social provider's response, links or creates a local user account, establishes an OP session, generates an authorization code, and finally redirects the user back to the Relying Party's `redirect_uri` (similar to the success case in step 5 of the email/password flow).

    **Administrator/Developer Notes:**

    *   **Backend Configuration Required:** For social login buttons to function, the Shadow SSO backend must be pre-configured by an administrator for each social provider. This involves:
        *   Registering an OAuth application with the social provider (e.g., Google Cloud Console, Facebook for Developers, GitHub OAuth Apps).
        *   Obtaining a Client ID and Client Secret from the social provider.
        *   Configuring these credentials and other provider-specific details (like scopes) as an Identity Provider (IdP) within the Shadow SSO backend system.
    *   **Frontend Responsibility:** The primary responsibility of the frontend is to provide the UI elements (buttons) and correctly redirect the user to the appropriate social login initiation endpoint on the Shadow SSO backend, passing along the current `flowId`. The rest of the social login dance (communication with the social provider, token exchange, user linking/creation) is handled by the Shadow SSO backend.
    *   **Error Handling:** If a social login attempt fails (e.g., user cancels, provider error, misconfiguration), the Shadow SSO backend should ideally redirect back to your frontend UI with appropriate error information in the URL query parameters, allowing your frontend to display a message to the user. The exact error reporting mechanism should be coordinated with the backend team.

4.  **Frontend Submits Authentication Data to OIDC Provider:**
    *   Once the user successfully authenticates on your frontend (e.g., enters correct username/password), make a `POST` request to the Shadow SSO backend:
        *   **Endpoint:** `POST /api/oidc/authenticate`
        *   **Request Body (JSON):**
            ```json
            {
                "flow_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx", // The flowId received in step 1
                "email": "user@example.com",    // User's email/username
                "password": "user_password"     // User's password
                // "csrf_token": "value_from_sso_csrf_token_cookie" // If CSRF token is sent in body
            }
            ```
        *   **Headers:**
            *   `Content-Type: application/json`
            *   **(Optional CSRF)** If CSRF protection is implemented via headers, include the CSRF token from the cookie in a custom header (e.g., `X-CSRF-Token: value_from_sso_csrf_token_cookie`).

5.  **Handling the Response from `/api/oidc/authenticate`:**
    *   **Success (HTTP 302 Found Redirect):**
        *   If authentication with the OIDC provider is successful, the `/api/oidc/authenticate` endpoint will **not** return a JSON body directly. Instead, it will issue an HTTP `302 Found` redirect.
        *   This redirect will target the Relying Party's `redirect_uri` (originally part of the OIDC request), including the `code` (authorization code) and `state` parameters.
        *   Your frontend application's HTTP client **must be configured to follow this redirect**. The browser will then be directed to the RP.
        *   The OIDC provider will also set its own session cookie (e.g., `sso_op_session`) in the user's browser to maintain their logged-in state with the provider itself. Your frontend typically doesn't need to interact with this cookie directly.
    *   **Failure (HTTP 4xx/5xx with JSON Error):**
        *   If authentication fails (e.g., invalid credentials, invalid `flowId`, server error), the endpoint will return a JSON error response.
        *   Example Error (HTTP 401 Unauthorized):
            ```json
            {
                "error": "invalid_credentials",
                "error_description": "Invalid email or password."
            }
            ```
        *   Example Error (HTTP 403 Forbidden - e.g., for invalid flowId):
            ```json
            {
                "error": "invalid_flow",
                "error_description": "Flow ID not found or expired."
            }
            ```
        *   Your frontend should handle these errors appropriately (e.g., display an error message to the user).

## Session Management with the OIDC Provider

*   After a successful login via `/api/oidc/authenticate`, the Shadow SSO backend will set an HTTP-only session cookie (e.g., `sso_op_session`) in the user's browser.
*   This cookie represents the user's authenticated session with the OIDC provider itself.
*   If the user is subsequently redirected to the `/oauth2/authorize` endpoint (e.g., by the same or a different RP) while this cookie is valid, the OIDC provider will recognize the user as already logged in and may skip the redirect to your Next.js UI, directly issuing an authorization code to the RP (subject to consent rules).
*   Your frontend application generally does not need to manage or interact with this `sso_op_session` cookie.

## CSRF Protection (TODO)

*   The `POST /api/oidc/authenticate` endpoint should be protected against Cross-Site Request Forgery (CSRF).
*   A common pattern is the double submit cookie method:
    1.  When the OIDC provider redirects to your Next.js UI (or when your UI calls `GET /api/oidc/flow/{flowId}`), the provider sets a CSRF token in a cookie (e.g., `sso_csrf_token`, `HttpOnly=false` so JavaScript can read it, or a separate non-HttpOnly cookie).
    2.  Your Next.js frontend reads this token from the cookie.
    3.  When making the `POST` request to `/api/oidc/authenticate`, your frontend includes this token in a custom HTTP header (e.g., `X-CSRF-Token`) or as part of the JSON request body.
    4.  The backend verifies that the token in the header/body matches the token in the cookie it originally set.
*   **Note:** The exact CSRF implementation details (cookie names, header names) will be finalized by the backend team. Please coordinate for the precise mechanism. For now, the backend placeholder for CSRF checking is present.

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
  the response headers forbid framing.

## Important Considerations

*   **HTTPS:** All communication between your frontend and the Shadow SSO backend APIs **must** be over HTTPS.
*   **Error Handling:** Implement robust error handling for API calls to provide clear feedback to the user.
*   **Configuration:** The base URL for the Shadow SSO backend APIs will be provided to you. The redirect URL for your Next.js login page (e.g., `https://your-nextjs-sso-ui.com/login`) needs to be configured in the Shadow SSO provider.

This guide provides a foundational understanding. Specific details or advanced scenarios (like detailed 2FA interactions) should be discussed with the backend team.
