# Shadow SSO API Documentation

This document outlines the gRPC API services provided by Shadow SSO.

## Services Overview

-   **AuthService**: Handles user authentication (login, logout) and session management.
-   **UserService**: Manages user lifecycle operations (registration, profile updates, status changes).
-   **ServiceAccountService**: Manages service accounts and their downloadable JSON keys.

---

## AuthService

Handles user authentication and session management.

### Methods

#### `Login(LoginRequest) returns (LoginResponse)`
Authenticates a user with email and password.
-   **Request**: `LoginRequest` (contains email, password)
-   **Response**: `LoginResponse` (contains access token, refresh token, user info)

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
-   **Request**: `ClearUserSessionsRequest` (contains optional `user_id` and `session_ids` to clear specific ones; if `session_ids` is empty, clears all for the target user)
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

*Further details on message structures can be found in the `proto/sso/v1/services.proto` file.*
