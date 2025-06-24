# Federation Architecture and API

This document outlines the architecture and API endpoints for the newly implemented federated identity system. This system allows users to log in or link their accounts using external OAuth2/OIDC providers like Google, Facebook, Apple, and GitHub.

## 1. Architecture Overview

The federation system is designed to integrate with the existing authentication and user management services. It introduces several new components and leverages existing ones:

### Core Components:

1.  **`internal/federation` Package:**
    *   **`OAuth2Provider` Interface (`provider.go`):** Defines a standard contract for interacting with external OAuth2/OIDC providers. Implementations exist for Google, Facebook, Apple, and GitHub.
    *   **`BaseProvider` (`provider.go`):** A base implementation of `OAuth2Provider` providing common functionalities, embedded by specific provider implementations.
    *   **`ExternalUserInfo` Struct (`provider.go`):** A standardized struct to hold user information retrieved from external providers.
    *   **`Service` (`service.go`):** Orchestrates the OAuth2 flows (authorization URL generation, token exchange, user info fetching) by interacting with `OAuth2Provider` implementations. It loads provider configurations from the database.
    *   **Provider Implementations (`google.go`, `facebook.go`, `apple.go`, `github.go`):** Concrete implementations of `OAuth2Provider` for each supported external IdP, handling their specific endpoint URLs, scopes, and user information parsing.

2.  **`services.FederationServer` (`services/federation_service.go`):**
    *   Implements the gRPC `FederationService` defined in `proto/sso/v1/federation_service.proto`.
    *   Handles the application-level logic for federation, including:
        *   Looking up or creating local user accounts.
        *   Linking local user accounts with external federated identities.
        *   Managing the account merging flow when an external identity's email matches an existing local account.
        *   Issuing local SSO tokens upon successful federated login or linking.
    *   Uses a TTL cache (`continuationCache`) for managing state during multi-step operations like account merging.
    *   Depends on:
        *   `internal/federation.Service`
        *   `domain.UserRepository`
        *   `domain.UserFederatedIdentityRepository`
        *   `domain.IdPRepository`
        *   `ssso.TokenService` (for local token issuance)
        *   `domain.SessionRepository`

3.  **Database Changes:**
    *   **`identity_providers` Collection (Existing, Leveraged):** Stores configurations for each external provider (Client ID, Client Secret, Scopes, etc.). Managed via the existing IdP Management service.
    *   **`user_federated_identities` Collection (New):**
        *   Links local user accounts (`users._id`) to external provider identities.
        *   Stores `user_id`, `provider_id` (references `identity_providers._id`), `provider_user_id` (unique ID from the external provider), and optionally `provider_email`, `provider_username`, and encrypted external tokens.
        *   **Schema:**
            ```json
            {
              "_id": ObjectId(),
              "user_id": String, // Local user ID
              "provider_id": String, // FK to identity_providers._id
              "provider_user_id": String, // User's ID at the external provider
              "provider_email": String, // Optional: Email from provider
              "provider_username": String, // Optional: Username/display name from provider
              "access_token": String, // Optional: Encrypted external access token
              "refresh_token": String, // Optional: Encrypted external refresh token
              "token_expires_at": ISODate, // Optional: Expiry for external access token
              "created_at": ISODate,
              "updated_at": ISODate
            }
            ```
        *   **Indexes:**
            *   Unique compound index on `(user_id, provider_id)`.
            *   Unique compound index on `(provider_id, provider_user_id)`.
            *   Index on `user_id`.

4.  **API Layer:**
    *   **gRPC `FederationService` (`proto/sso/v1/federation_service.proto`):** Defines the service contract for federation operations (see section 2).
    *   **HTTP Handlers (`api/gin/federation_handlers.go`):** Provides user-facing HTTP endpoints that orchestrate browser redirects and call the gRPC `FederationService`. These are necessary because OAuth2 flows involve browser redirects which are not directly manageable via gRPC.

### Flows:

1.  **Initiate Federated Login:**
    *   User clicks "Login with Google" (or other provider) on the client application.
    *   Client app calls its backend, which in turn calls the SSO system's HTTP endpoint: `GET /federation/{provider}/login`.
    *   The HTTP handler calls `FederationService.InitiateFederatedLogin` (gRPC).
    *   This RPC generates a `state` parameter (for CSRF protection) and constructs the authorization URL for the external provider.
    *   The HTTP handler stores the `state` in a secure, HttpOnly cookie and redirects the user's browser to the external provider's authorization URL.

2.  **Handle External Provider Callback:**
    *   User authenticates with the external provider.
    *   External provider redirects the user back to the SSO system's callback URL: `GET /federation/callback/{provider}` (or POST for Apple). The callback includes an `authorization_code` and the `state`.
    *   The HTTP callback handler:
        *   Retrieves the `state` from the cookie and verifies it against the `state` parameter in the callback request.
        *   Calls `FederationService.HandleFederatedCallback` (gRPC) with the `provider_name`, `code`, and validated `state`.
    *   The `FederationService.HandleFederatedCallback` RPC:
        *   Uses `internal/federation.Service` to exchange the `code` for tokens from the external provider and fetch the external user's profile.
        *   **Account Logic:**
            1.  Checks if the `provider_user_id` is already linked in `user_federated_identities`. If yes, logs in the corresponding local user.
            2.  If the current SSO session is already authenticated (user is logged in): Links the new external identity to the currently logged-in local user.
            3.  If no existing link and user is not logged in:
                *   Checks if a local user exists with the email address provided by the external provider.
                    *   If yes, and that local account is not already linked to *this* provider with a *different* external ID: Initiates the merge flow. Returns `MERGE_REQUIRED_EMAIL_EXISTS` status with a `continuation_token`.
                    *   If a conflict exists (local user email matches, but is already linked to this provider via a different external account): Returns a conflict message.
                *   If no local user with that email exists: Creates a new local user account and links it to the external identity. Logs in the new user.
        *   Issues local SSO tokens (access and refresh) for the successfully authenticated/linked/created local user.
    *   The HTTP callback handler receives the response from the gRPC service and communicates the outcome to the client application (e.g., by setting session cookies with local SSO tokens and redirecting, or returning tokens in the response body for SPAs).

3.  **Account Merging (Simplified Flow):**
    *   If `HandleFederatedCallback` returns `MERGE_REQUIRED_EMAIL_EXISTS` with a `continuation_token`:
        *   The client UI uses this token to call `FederationService.PromptMergeFederatedAccount` (gRPC) to get details for the user to confirm.
        *   If the user confirms, the client UI calls `FederationService.ConfirmMergeFederatedAccount` (gRPC) with the `continuation_token`.
        *   This RPC retrieves the context, creates the link in `user_federated_identities`, and logs the user in.
    *   **Note:** The current merge flow implies consent from the user performing the federated login. A full implementation would add an email verification step for the owner of the existing local account.

4.  **Managing Linked Identities:**
    *   Authenticated users can list their linked identities via `FederationService.ListUserFederatedIdentities`.
    *   Authenticated users can remove a linked identity via `FederationService.RemoveUserFederatedIdentity`.

## 2. gRPC API Endpoints (`sso.v1.FederationService`)

Defined in `proto/sso/v1/federation_service.proto`.

### `rpc InitiateFederatedLogin(InitiateFederatedLoginRequest) returns (InitiateFederatedLoginResponse)`

*   **Purpose:** Starts the federated login flow for a specified provider.
*   **Request (`InitiateFederatedLoginRequest`):**
    *   `provider_name (string)`: The name of the external provider (e.g., "google", "facebook").
*   **Response (`InitiateFederatedLoginResponse`):**
    *   `authorization_url (string)`: The URL to redirect the user's browser to for authentication with the external provider.
    *   `state (string)`: A unique, unguessable string generated by the server. The calling HTTP handler should store this (e.g., in a secure cookie) and verify it during the callback phase to prevent CSRF attacks.

### `rpc HandleFederatedCallback(HandleFederatedCallbackRequest) returns (HandleFederatedCallbackResponse)`

*   **Purpose:** Processes the callback from the external identity provider after user authentication. Exchanges the authorization code, fetches user info, performs account linking/creation/merging, and issues local session tokens.
*   **Request (`HandleFederatedCallbackRequest`):**
    *   `provider_name (string)`: The name of the provider.
    *   `state (string)`: The state parameter received from the provider in the callback. This should be validated against the stored state by the calling HTTP handler or by this RPC if the stored state is passed.
    *   `code (string)`: The authorization code received from the provider.
    *   *(For Apple `form_post`)*: May include `id_token` and `user` fields if applicable, though the primary mechanism is the `code`.
*   **Response (`HandleFederatedCallbackResponse`):**
    *   `status (Status)`: An enum indicating the outcome:
        *   `LOGIN_SUCCESSFUL`: User logged in with an existing link.
        *   `ACCOUNT_LINKED_LOGIN`: New external account linked to an existing (possibly authenticated) local user, then logged in.
        *   `NEW_USER_REGISTRATION_REQUIRED`: New user from external provider, no local account. (Current implementation auto-creates the user and logs them in, effectively using `LOGIN_SUCCESSFUL` or `ACCOUNT_LINKED_LOGIN`.)
        *   `MERGE_REQUIRED_EMAIL_EXISTS`: External account's email matches an existing local account. User action (merge confirmation) is needed.
    *   `message (string)`: A user-friendly message.
    *   `access_token (string)`, `token_type (string)`, `expires_in (int32)`, `refresh_token (string)`, `id_token (string)`: Local SSO session tokens if login was successful.
    *   `user_info (sso.v1.User)`: Information about the local user account.
    *   `provider_user_id (string)`, `provider_email (string)`, `provider_name (string)`: Information from the external provider, relevant for merge/registration continuation.
    *   `continuation_token (string)`: A temporary token to secure subsequent calls for merge confirmation or registration completion.

### `rpc ListUserFederatedIdentities(ListUserFederatedIdentitiesRequest) returns (ListUserFederatedIdentitiesResponse)`

*   **Purpose:** Lists all federated identities linked to the currently authenticated user.
*   **Authentication:** Requires an active user session (local SSO token).
*   **Request (`ListUserFederatedIdentitiesRequest`):** Empty (user ID is taken from authentication context).
*   **Response (`ListUserFederatedIdentitiesResponse`):**
    *   `identities (repeated FederatedIdentityInfo)`: A list of linked identities.
        *   `FederatedIdentityInfo`: Contains `id` (link record ID), `provider_id`, `provider_name`, `provider_user_id`, `provider_email`, `provider_username`, `created_at`.

### `rpc RemoveUserFederatedIdentity(RemoveUserFederatedIdentityRequest) returns (google.protobuf.Empty)`

*   **Purpose:** Allows an authenticated user to unlink one of their external federated identities.
*   **Authentication:** Requires an active user session.
*   **Request (`RemoveUserFederatedIdentityRequest`):**
    *   `provider_user_id_to_remove (string)`: The unique ID of the user *at the external provider* for the link to be removed (e.g., Google's `sub`).
    *   `provider_name (string)`: The name of the provider for this identity (e.g., "google").
*   **Response (`google.protobuf.Empty`):** Empty on success.

### `rpc PromptMergeFederatedAccount(PromptMergeFederatedAccountRequest) returns (PromptMergeFederatedAccountResponse)`

*   **Purpose:** Provides information to the user when their external identity's email matches an existing local account, allowing them to decide whether to link/merge them.
*   **Request (`PromptMergeFederatedAccountRequest`):**
    *   `continuation_token (string)`: The token received from `HandleFederatedCallbackResponse` when `status` was `MERGE_REQUIRED_EMAIL_EXISTS`.
*   **Response (`PromptMergeFederatedAccountResponse`):**
    *   `message (string)`: A descriptive message for the user.
    *   `existing_local_user_email (string)`: The email of the existing local account.
    *   `provider_name (string)`: The name of the external provider.

### `rpc ConfirmMergeFederatedAccount(ConfirmMergeFederatedAccountRequest) returns (HandleFederatedCallbackResponse)`

*   **Purpose:** Finalizes the linking of an external federated identity to an existing local user account, after the user has confirmed the merge.
*   **Request (`ConfirmMergeFederatedAccountRequest`):**
    *   `continuation_token (string)`: The token received from `HandleFederatedCallbackResponse`.
*   **Response (`HandleFederatedCallbackResponse`):** Similar to a successful login response, providing local SSO tokens and user information for the (now merged) local account. `status` will typically be `ACCOUNT_LINKED_LOGIN`.

## 3. HTTP API Endpoints (Gin Handlers)

These HTTP endpoints are user-facing and orchestrate the browser-based OAuth2 redirect flows. They call the gRPC `FederationService` internally.

### `GET /federation/{provider}/login`

*   **Purpose:** Initiates the federated login flow for the specified `{provider}`.
*   **Path Parameter:**
    *   `provider (string)`: The name of the external provider (e.g., "google", "github").
*   **Actions:**
    1.  Calls the `FederationService.InitiateFederatedLogin` gRPC method.
    2.  Receives an `authorization_url` and a `state` string.
    3.  Stores the `state` in a secure, HttpOnly cookie (e.g., `sso_federation_state`) with a short expiry.
    4.  Redirects the user's browser (HTTP 302 Found) to the `authorization_url`.
*   **Success Response:** HTTP 302 Redirect.
*   **Error Responses:**
    *   HTTP 400 Bad Request: If `provider` is missing.
    *   HTTP 404 Not Found: If the specified `provider` is not found or configured.
    *   HTTP 500 Internal Server Error: If an unexpected error occurs.

### `GET /federation/callback/{provider}` (also `POST` for Apple)

*   **Purpose:** Handles the callback from the external identity provider after the user has authenticated.
*   **Path Parameter:**
    *   `provider (string)`: The name of the external provider.
*   **Query/Form Parameters (from external IdP):**
    *   `code (string)`: The authorization code (usually for GET).
    *   `state (string)`: The state parameter.
    *   `error (string)` (Optional): If the IdP returns an error (e.g., "access_denied").
    *   `error_description (string)` (Optional): Description of the error.
    *   *(Apple specific, via POST)*: `id_token (string)`, `user (string)` may also be present.
*   **Actions:**
    1.  Retrieves the `state` parameter from the request (query for GET, form for POST).
    2.  Retrieves the previously stored `state` from the `sso_federation_state` cookie and deletes the cookie.
    3.  Compares the two `state` values. If they don't match, it's a potential CSRF attack; abort and show an error.
    4.  If an `error` parameter is present from the IdP, display an appropriate error to the user.
    5.  Calls the `FederationService.HandleFederatedCallback` gRPC method with the `provider`, `code`, and validated `state`.
    6.  Processes the gRPC response:
        *   If login/linking is successful: Issues local SSO session cookies (or returns tokens for SPAs) and redirects the user to the application's post-login page.
        *   If merge is required: Redirects the user to a UI page to handle the merge flow, potentially passing the `continuation_token`.
        *   If registration completion is required: Redirects to a registration completion page.
*   **Success Response:** Typically an HTTP 302 Redirect to the application, or a JSON response with tokens/status for SPAs.
*   **Error Responses:**
    *   HTTP 400 Bad Request: If state is missing/mismatched, code is missing, or IdP returned an error.
    *   HTTP 500 Internal Server Error: If callback processing fails internally.

## 4. Configuration

To enable and configure federated identity providers:

*   Use the existing IdP Management service/interface.
*   For each provider (Google, Facebook, Apple, GitHub):
    *   Create an `IdentityProvider` record in the `identity_providers` collection.
    *   `name`: Must match the expected provider key (e.g., "google", "facebook", "apple", "github").
    *   `type`: `OIDC`.
    *   `is_enabled`: `true`.
    *   `oidc_client_id`: The Client ID obtained from the provider's developer console.
    *   `oidc_client_secret`: The Client Secret obtained from the provider.
        *   **For Apple:** This must be the pre-generated client secret JWT. The system currently does not dynamically generate this JWT.
    *   `oidc_issuer_url`: The issuer URL for the provider (e.g., `https://accounts.google.com`, `https://appleid.apple.com`). For GitHub and Facebook, this can be their main domain or Graph API URL as a convention, as their `oauth2.Endpoint` is hardcoded in the respective provider implementations.
    *   `oidc_scopes`: A list of scopes to request (e.g., `["openid", "profile", "email"]` for Google; `["read:user", "user:email"]` for GitHub; `["public_profile", "email"]` for Facebook; `["name", "email"]` for Apple). The specific provider implementations might add default necessary scopes if not provided.
    *   The callback/redirect URI configured in the external provider's settings must match what the SSO system expects, typically `[SSO_BASE_URL]/federation/callback/{provider_name}`.

## 5. Security Considerations

*   **State Parameter (CSRF):** The `state` parameter is used to prevent Cross-Site Request Forgery attacks. It's generated by the SSO, stored in a secure HttpOnly cookie, and verified on callback.
*   **Client Secrets:** External provider client secrets are stored in the `identity_providers` collection. They should be encrypted at rest or managed via an external secrets manager for production deployments. The current schema only marks the field as non-JSON serializable (`json:"-"`).
*   **Apple Client Secret JWT:** Requires secure management of the private key used to sign it and periodic regeneration.
*   **Open Redirects:** Ensure that any redirect URLs (especially the final redirect after login) are validated against a whitelist to prevent open redirector vulnerabilities.
*   **Token Encryption:** If external provider tokens (`access_token`, `refresh_token`) are stored in `user_federated_identities`, they must be encrypted at rest.
*   **Continuation Tokens:** These temporary tokens used for merge/registration flows must be unguessable, short-lived, and single-use. Storing them server-side (e.g., TTL cache) is preferred over passing all context through the client.

This documentation should provide a good overview for developers and administrators working with the new federation feature.

## 6. Testing

The core federation logic within the `internal/federation` package is unit-tested to ensure reliability. Key dependencies, such as `domain.IdPRepository` and the `federation.OAuth2Provider` interface, are mocked using `gomock`. This allows for isolated testing of the `federation.Service` component, covering various scenarios including successful authentication flows, error conditions, and provider interactions. The `mockgen` tool is utilized to generate the mock implementations based on the defined interfaces, including comments for clarity.
[end of docs/federation.md]
