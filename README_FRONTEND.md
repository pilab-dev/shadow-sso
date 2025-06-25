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

## Important Considerations

*   **HTTPS:** All communication between your frontend and the Shadow SSO backend APIs **must** be over HTTPS.
*   **Error Handling:** Implement robust error handling for API calls to provide clear feedback to the user.
*   **Configuration:** The base URL for the Shadow SSO backend APIs will be provided to you. The redirect URL for your Next.js login page (e.g., `https://your-nextjs-sso-ui.com/login`) needs to be configured in the Shadow SSO provider.

This guide provides a foundational understanding. Specific details or advanced scenarios (like detailed 2FA interactions) should be discussed with the backend team.
