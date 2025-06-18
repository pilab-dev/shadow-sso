# Shadow SSO API Documentation

This document outlines the gRPC API services provided by Shadow SSO.

## Services Overview

-   **AuthService**: Handles user authentication (login, logout, 2FA verification) and session management.
-   **UserService**: Manages user lifecycle operations (registration, profile updates, status changes).
-   **ServiceAccountService**: Manages service accounts and their downloadable JSON keys.
-   **TwoFactorService**: Provides methods for users to manage their Two-Factor Authentication (2FA) settings, primarily TOTP.
-   **ClientManagementService**: Manages OAuth2 client configurations (registration, updates, etc.).
-   **IdPManagementService**: Manages external Identity Provider (IdP) configurations.

---

## AuthService

Handles user authentication, 2FA verification, and session management.

### Methods

#### `Login(LoginRequest) returns (LoginResponse)`
Authenticates a user with email and password. If 2FA is enabled for the user, this response will indicate that a second factor is required.
-   **Request**: `LoginRequest` (contains email, password)
-   **Response**: `LoginResponse` (may contain access/refresh tokens and user info if 2FA is not required, OR `two_factor_required=true` and a `two_factor_session_token` if 2FA is the next step).

#### `Verify2FA(Verify2FARequest) returns (LoginResponse)`
Verifies a Two-Factor Authentication code (TOTP or recovery code) after a successful primary authentication (e.g., password login) that indicated 2FA was required.
-   **Request**: `Verify2FARequest` (contains `user_id`, `totp_code`, and `two_factor_session_token` from the initial login step)
-   **Response**: `LoginResponse` (contains access token, refresh token, user info upon successful 2FA verification)

#### `Logout(LogoutRequest) returns (google.protobuf.Empty)`
Logs out the currently authenticated user by invalidating their session/token.
-   **Request**: `LogoutRequest` (empty, token from context is used)
-   **Response**: `google.protobuf.Empty`

#### `ListUserSessions(ListUserSessionsRequest) returns (ListUserSessionsResponse)`
Lists active sessions for a user. Defaults to the current authenticated user if `user_id` in request is empty. Admin can specify a `user_id`.
-   **Request**: `ListUserSessionsRequest` (contains optional `user_id`)
-   **Response**: `ListUserSessionsResponse` (contains a list of `SessionInfo`)

#### `ClearUserSessions(ClearUserSessionsRequest) returns (google.protobuf.Empty)`
Clears (revokes) sessions for a user.
-   **Request**: `ClearUserSessionsRequest` (contains optional `user_id` and `session_ids` to clear specific ones; if `session_ids` is empty, clears all for the target user, or all *other* sessions if target is self)
-   **Response**: `google.protobuf.Empty`

---

## UserService

Manages user lifecycle operations.

### Methods

#### `RegisterUser(RegisterUserRequest) returns (RegisterUserResponse)`
Registers a new user. This operation may require admin privileges.
-   **Request**: `RegisterUserRequest` (contains email, password, first name, last name)
-   **Response**: `RegisterUserResponse` (contains the created `User` object)

#### `ActivateUser(ActivateUserRequest) returns (google.protobuf.Empty)`
Activates a user account (e.g., after email verification or admin approval).
-   **Request**: `ActivateUserRequest` (contains `user_id`)
-   **Response**: `google.protobuf.Empty`

#### `LockUser(LockUserRequest) returns (google.protobuf.Empty)`
Locks a user account, preventing login.
-   **Request**: `LockUserRequest` (contains `user_id`)
-   **Response**: `google.protobuf.Empty`

#### `ListUsers(ListUsersRequest) returns (ListUsersResponse)`
Lists users with pagination. Requires admin privileges.
-   **Request**: `ListUsersRequest` (contains `page_size`, `page_token`)
-   **Response**: `ListUsersResponse` (contains a list of `User` objects and `next_page_token`)

#### `GetUser(GetUserRequest) returns (GetUserResponse)`
Retrieves details for a specific user by ID or email. Requires admin privileges or user accessing their own data.
-   **Request**: `GetUserRequest` (contains `user_id` which can be an ID or email)
-   **Response**: `GetUserResponse` (contains the `User` object)

#### `ChangePassword(ChangePasswordRequest) returns (google.protobuf.Empty)`
Changes a user's password. Can be self-service (requires old password) or admin-initiated.
-   **Request**: `ChangePasswordRequest` (contains `user_id`, optional `old_password`, `new_password`)
-   **Response**: `google.protobuf.Empty`

---

## ServiceAccountService

Manages service accounts and their downloadable JSON keys.

### Methods

#### `CreateServiceAccountKey(CreateServiceAccountKeyRequest) returns (CreateServiceAccountKeyResponse)`
Creates a new service account and/or a JSON key for it.
-   **Request**: `CreateServiceAccountKeyRequest` (contains `project_id`, optional `client_email`, `display_name`)
-   **Response**: `CreateServiceAccountKeyResponse` (contains the downloadable `ServiceAccountKey` JSON structure and `service_account_id`)

#### `ListServiceAccountKeys(ListServiceAccountKeysRequest) returns (ListServiceAccountKeysResponse)`
Lists metadata of active public keys for a given service account.
-   **Request**: `ListServiceAccountKeysRequest` (contains `service_account_id`)
-   **Response**: `ListServiceAccountKeysResponse` (contains a list of `StoredServiceAccountKeyInfo`)

#### `DeleteServiceAccountKey(DeleteServiceAccountKeyRequest) returns (google.protobuf.Empty)`
Deletes (revokes) a specific service account key.
-   **Request**: `DeleteServiceAccountKeyRequest` (contains `service_account_id`, `key_id`)
-   **Response**: `google.protobuf.Empty`

---

## TwoFactorService

Provides methods for users to manage their Two-Factor Authentication (2FA) settings, primarily TOTP. These are typically self-service operations.

### Methods

#### `InitiateTOTPSetup(InitiateTOTPSetupRequest) returns (InitiateTOTPSetupResponse)`
Initiates TOTP setup for the authenticated user. Generates a new secret and QR code URI.
-   **Request**: `InitiateTOTPSetupRequest` (empty)
-   **Response**: `InitiateTOTPSetupResponse` (contains `secret`, `qr_code_uri`)

#### `VerifyAndEnableTOTP(VerifyAndEnableTOTPRequest) returns (VerifyAndEnableTOTPResponse)`
Verifies a TOTP code and enables 2FA for the user. Returns recovery codes.
-   **Request**: `VerifyAndEnableTOTPRequest` (contains `totp_code`)
-   **Response**: `VerifyAndEnableTOTPResponse` (contains `recovery_codes`)

#### `Disable2FA(Disable2FARequest) returns (google.protobuf.Empty)`
Disables 2FA for the authenticated user. Requires re-authentication (password or 2FA code).
-   **Request**: `Disable2FARequest` (contains `password_or_2fa_code`)
-   **Response**: `google.protobuf.Empty`

#### `GenerateRecoveryCodes(GenerateRecoveryCodesRequest) returns (GenerateRecoveryCodesResponse)`
Generates new recovery codes for a 2FA-enabled user, invalidating old ones. May require re-authentication.
-   **Request**: `GenerateRecoveryCodesRequest` (contains optional `password_or_2fa_code`)
-   **Response**: `GenerateRecoveryCodesResponse` (contains new `recovery_codes`)

---

## ClientManagementService

Manages OAuth2 client configurations. These operations typically require administrator privileges.

### Methods

#### `RegisterClient(RegisterClientRequest) returns (RegisterClientResponse)`
Registers a new OAuth2 client application.
-   **Request**: `RegisterClientRequest` (contains client details like name, type, redirect URIs, scopes, etc.)
-   **Response**: `RegisterClientResponse` (contains the registered `ClientProto`, including generated `client_id` and `client_secret` if confidential)

#### `GetClient(GetClientRequest) returns (GetClientResponse)`
Retrieves details for a specific OAuth2 client by its ID.
-   **Request**: `GetClientRequest` (contains `client_id`)
-   **Response**: `GetClientResponse` (contains `ClientProto`; `client_secret` is omitted)

#### `ListClients(ListClientsRequest) returns (ListClientsResponse)`
Lists registered OAuth2 clients with pagination.
-   **Request**: `ListClientsRequest` (contains `page_size`, `page_token`)
-   **Response**: `ListClientsResponse` (contains a list of `ClientProto` and `next_page_token`; `client_secret` is omitted)

#### `UpdateClient(UpdateClientRequest) returns (UpdateClientResponse)`
Updates an existing OAuth2 client's configuration.
-   **Request**: `UpdateClientRequest` (contains `client_id` and fields to update)
-   **Response**: `UpdateClientResponse` (contains the updated `ClientProto`; `client_secret` is omitted)

#### `DeleteClient(DeleteClientRequest) returns (google.protobuf.Empty)`
Deletes an OAuth2 client by its ID.
-   **Request**: `DeleteClientRequest` (contains `client_id`)
-   **Response**: `google.protobuf.Empty`

---

## IdPManagementService

Manages configurations for external Identity Providers (IdPs) like OIDC or SAML providers. These operations typically require administrator privileges.

### Methods

#### `AddIdP(AddIdPRequest) returns (AddIdPResponse)`
Adds a new external IdP configuration.
-   **Request**: `AddIdPRequest` (contains IdP details like name, type, OIDC settings, attribute mappings)
-   **Response**: `AddIdPResponse` (contains the created `IdentityProviderProto`; OIDC client secret is omitted)

#### `GetIdP(GetIdPRequest) returns (GetIdPResponse)`
Retrieves an IdP configuration by its ID.
-   **Request**: `GetIdPRequest` (contains `id`)
-   **Response**: `GetIdPResponse` (contains `IdentityProviderProto`; OIDC client secret is omitted)

#### `ListIdPs(ListIdPsRequest) returns (ListIdPsResponse)`
Lists all configured IdPs, with an option to filter by enabled status.
-   **Request**: `ListIdPsRequest` (contains `only_enabled` flag)
-   **Response**: `ListIdPsResponse` (contains a list of `IdentityProviderProto`; OIDC client secrets are omitted)

#### `UpdateIdP(UpdateIdPRequest) returns (UpdateIdPResponse)`
Updates an existing IdP configuration.
-   **Request**: `UpdateIdPRequest` (contains `id` and fields to update)
-   **Response**: `UpdateIdPResponse` (contains the updated `IdentityProviderProto`; OIDC client secret is omitted)

#### `DeleteIdP(DeleteIdPRequest) returns (google.protobuf.Empty)`
Deletes an IdP configuration by its ID.
-   **Request**: `DeleteIdPRequest` (contains `id`)
-   **Response**: `google.protobuf.Empty`

---

*Further details on message structures can be found in the respective `.proto` files in `proto/sso/v1/`.*
