# Shadow SSO API Documentation

This document outlines the comprehensive gRPC API services provided by Shadow SSO, covering authentication, user management, MFA, and administrative operations.

## Services Overview

### 🔐 Core Authentication Services
-   **AuthService**: User authentication, session management, and OAuth2 flows
-   **TwoFactorService**: Multi-factor authentication (TOTP, HOTP, Email, Push MFA)

### 👤 User Management Services
-   **UserService**: Complete user lifecycle management (registration, profiles, password reset)
-   **ClientManagementService**: OAuth2 client configuration and management
-   **IdPManagementService**: External identity provider integration
-   **ServiceAccountService**: Machine identity and service account management

### 📱 Advanced Features
-   **FederationService**: Cross-domain identity federation
-   **PhoneVerificationService**: SMS-based phone number verification
-   **MFAService**: Email-based multi-factor authentication
-   **PushMFAService**: Firebase-powered push notification MFA

---

## AuthService

Handles user authentication, session management, and OAuth2/OIDC flows with comprehensive MFA support.

### Authentication Methods

#### `Login(LoginRequest) returns (LoginResponse)`
Primary user authentication with automatic MFA detection.
-   **Request**: `LoginRequest` (email, password)
-   **Response**:
  - If MFA disabled: Complete authentication with tokens
  - If MFA enabled: `two_factor_required=true` with session token for MFA verification
-   **Features**: Account lockout protection, failed attempt tracking, audit logging

#### `Verify2FA(Verify2FARequest) returns (LoginResponse)`
Completes MFA authentication after successful password verification.
-   **Request**: `Verify2FARequest` (user_id, totp_code/recovery_code, two_factor_session_token)
-   **Response**: Complete authentication tokens and user info
-   **Supported Methods**: TOTP, HOTP, Recovery Codes

#### `Logout(LogoutRequest) returns (google.protobuf.Empty)`
Secure logout with comprehensive session cleanup.
-   **Process**:
  1. Revoke JWT token from denylist
  2. Mark session as revoked in database
  3. Update session expiry
  4. Decrement active session counters
-   **Security**: Prevents token replay attacks

### Session Management

#### `ListUserSessions(ListUserSessionsRequest) returns (ListUserSessionsResponse)`
Retrieve active sessions for monitoring and security.
-   **Request**: `ListUserSessionsRequest` (optional user_id, pagination)
-   **Response**: `ListUserSessionsResponse` (session list with metadata)
-   **Permissions**: Self or admin access

#### `ClearUserSessions(ClearUserSessionsRequest) returns (google.protobuf.Empty)`
Revoke specific or all user sessions for security.
-   **Request**: `ClearUserSessionsRequest` (user_id, optional session_ids)
-   **Behavior**:
  - Specific sessions: Revoke only listed sessions
  - All sessions: Revoke all sessions for user
  - Self-cleanup: Optionally preserve current session

### OAuth2/OIDC Flow Methods

#### `GetConsentInfo(GetConsentInfoRequest) returns (GetConsentInfoResponse)`
Retrieve consent information for OAuth2 authorization flows.
-   **Request**: `GetConsentInfoRequest` (flow_id)
-   **Response**: Client info, requested scopes with descriptions

#### `SubmitConsent(SubmitConsentRequest) returns (SubmitConsentResponse)`
User consent approval for OAuth2 scopes.
-   **Request**: `SubmitConsentRequest` (flow_id, accepted_scopes, remember_consent)
-   **Response**: Authorization code redirect URL

#### `DenyConsent(DenyConsentRequest) returns (DenyConsentResponse)`
User consent denial for OAuth2 scopes.
-   **Request**: `DenyConsentRequest` (flow_id)
-   **Response**: Error redirect URL to client

---

## UserService

Comprehensive user lifecycle management including registration, profiles, security, and verification.

### User Lifecycle Management

#### `RegisterUser(RegisterUserRequest) returns (RegisterUserResponse)`
Create new user accounts with initial security setup.
-   **Request**: `RegisterUserRequest` (email, password, first_name, last_name)
-   **Process**:
  1. Email uniqueness validation
  2. Password hashing with bcrypt
  3. User creation with "pending" status
  4. Audit logging
-   **Security**: Duplicate prevention, secure password storage

#### `ActivateUser(ActivateUserRequest) returns (google.protobuf.Empty)`
Activate pending user accounts after verification.
-   **Request**: `ActivateUserRequest` (user_id)
-   **Process**: Status change from "pending" to "active"

#### `LockUser(LockUserRequest) returns (google.protobuf.Empty)`
Temporarily disable user access for security.
-   **Request**: `LockUserRequest` (user_id)
-   **Use Cases**: Security incidents, account recovery

### User Information & Administration

#### `ListUsers(ListUsersRequest) returns (ListUsersResponse)`
Administrative user listing with pagination.
-   **Request**: `ListUsersRequest` (page_size, page_token)
-   **Response**: Paginated user list with metadata
-   **Permissions**: Admin access required

#### `GetUser(GetUserRequest) returns (GetUserResponse)`
Retrieve detailed user information.
-   **Request**: `GetUserRequest` (user_id or email)
-   **Permissions**: Self access or admin privileges

#### `UpdateUser(UpdateUserRequest) returns (UpdateUserResponse)`
Modify user profile information.
-   **Request**: `UpdateUserRequest` (user_id, fields to update)
-   **Fields**: Email, names, profile data, preferences

#### `DeleteUser(DeleteUserRequest) returns (google.protobuf.Empty)`
Permanently remove user accounts.
-   **Request**: `DeleteUserRequest` (user_id)
-   **Process**: Complete data cleanup and audit logging

### Security & Password Management

#### `ChangePassword(ChangePasswordRequest) returns (google.protobuf.Empty)`
Secure password updates with validation.
-   **Request**: `ChangePasswordRequest` (user_id, old_password, new_password)
-   **Modes**:
  - **Self-service**: Requires current password verification
  - **Admin reset**: Admin can change without old password
-   **Security**: Password strength validation, audit logging

### Password Reset Flow

#### `RequestPasswordReset(RequestPasswordResetRequest) returns (RequestPasswordResetResponse)`
Initiate password reset process.
-   **Request**: `RequestPasswordResetRequest` (email)
-   **Process**:
  1. Generate secure reset token
  2. Store token with expiry
  3. Send reset email
-   **Security**: Time-limited tokens, rate limiting

#### `ResetPassword(ResetPasswordRequest) returns (ResetPasswordResponse)`
Complete password reset with token validation.
-   **Request**: `ResetPasswordRequest` (token, new_password)
-   **Process**:
  1. Validate token expiry and authenticity
  2. Update password hash
  3. Clear reset token
-   **Security**: Single-use tokens, secure password hashing

### Phone Number Management

#### `SetPhoneNumber(SetPhoneNumberRequest) returns (google.protobuf.Empty)`
Associate phone number with user account.
-   **Request**: `SetPhoneNumberRequest` (user_id, phone_number)

#### `SendPhoneVerificationOtp(SendPhoneVerificationOtpRequest) returns (SendPhoneVerificationOtpResponse)`
Send SMS verification code to phone number.
-   **Request**: `SendPhoneVerificationOtpRequest` (user_id)
-   **Process**: Generate and send OTP via SMS service

#### `VerifyPhoneNumber(VerifyPhoneNumberRequest) returns (VerifyPhoneNumberResponse)`
Confirm phone number ownership with OTP.
-   **Request**: `VerifyPhoneNumberRequest` (user_id, otp)
-   **Process**: Validate OTP and mark phone as verified

### Email Verification

#### `SendEmailVerification(SendEmailVerificationRequest) returns (google.protobuf.Empty)`
Send email verification link.
-   **Process**: Generate verification token and send email

#### `VerifyEmail(VerifyEmailRequest) returns (VerifyEmailResponse)`
Confirm email ownership with verification token.

### Account Security Features

#### `IncrementFailedLoginAttempts(IncrementFailedLoginAttemptsRequest) returns (IncrementFailedLoginAttemptsResponse)`
Track failed login attempts for security monitoring.

#### `ResetFailedLoginAttempts(ResetFailedLoginAttemptsRequest) returns (google.protobuf.Empty)`
Reset failed attempt counter after successful login.

#### `SetEmailAsVerified(SetEmailAsVerifiedRequest) returns (google.protobuf.Empty)`
Mark email as verified (admin function).

### Token Management

#### `StoreEmailVerificationToken(StoreEmailVerificationTokenRequest) returns (google.protobuf.Empty)`
Store email verification token with expiry.

#### `GetUserByEmailVerificationToken(GetUserByEmailVerificationTokenRequest) returns (GetUserByEmailVerificationTokenResponse)`
Validate email verification token.

#### `ClearEmailVerificationToken(ClearEmailVerificationTokenRequest) returns (google.protobuf.Empty)`
Remove used or expired verification tokens.

#### `StorePasswordResetToken(StorePasswordResetTokenRequest) returns (google.protobuf.Empty)`
Store password reset token securely.

#### `GetUserByPasswordResetToken(GetUserByPasswordResetTokenRequest) returns (GetUserByPasswordResetTokenResponse)`
Validate password reset token.

#### `ClearPasswordResetToken(ClearPasswordResetTokenRequest) returns (google.protobuf.Empty)`
Clean up used password reset tokens.

#### `UpdateUserPassword(UpdateUserPasswordRequest) returns (google.protobuf.Empty)`
Direct password update (admin function).

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

Comprehensive multi-factor authentication management supporting multiple MFA methods and advanced security features.

### TOTP (Time-based One-Time Password)

#### `InitiateTOTPSetup(InitiateTOTPSetupRequest) returns (InitiateTOTPSetupResponse)`
Initialize TOTP authenticator setup.
-   **Process**:
  1. Generate cryptographically secure secret
  2. Create QR code URI for authenticator apps
  3. Store temporary secret (not yet enabled)
-   **Response**: Base32 secret and otpauth:// URI

#### `VerifyAndEnableTOTP(VerifyAndEnableTOTPRequest) returns (VerifyAndEnableTOTPResponse)`
Complete TOTP setup and enable 2FA.
-   **Request**: TOTP code from authenticator app
-   **Process**:
  1. Validate TOTP code against stored secret
  2. Enable 2FA for user account
  3. Generate and return recovery codes
-   **Security**: Single-use verification, secure code validation

### HOTP (HMAC-based One-Time Password)

#### `InitiateHOTPSetup(InitiateHOTPSetupRequest) returns (InitiateHOTPSetupResponse)`
Initialize HOTP hardware token setup.
-   **Process**: Generate secret and QR code for HOTP devices
-   **Response**: Secret, QR URI, initial counter value

#### `VerifyAndEnableHOTP(VerifyAndEnableHOTPRequest) returns (VerifyAndEnableHOTPResponse)`
Complete HOTP setup with counter validation.

### Email-Based MFA

#### `InitiateEmailMFASetup(InitiateEmailMFASetupRequest) returns (InitiateEmailMFASetupResponse)`
Start email MFA configuration.
-   **Process**: Send verification OTP to user's email
-   **Response**: Setup confirmation message

#### `VerifyAndEnableEmailMFA(VerifyAndEnableEmailMFARequest) returns (VerifyAndEnableEmailMFAResponse)`
Complete email MFA setup.
-   **Request**: OTP received via email
-   **Process**: Validate OTP and enable email MFA

### Push Notification MFA (Firebase)

#### `InitiatePushMFASetup(InitiatePushMFASetupRequest) returns (InitiatePushMFASetupResponse)`
Register device token for push notifications.
-   **Request**: Firebase device token
-   **Process**: Store device token for push notifications

#### `VerifyAndEnablePushMFA(VerifyAndEnablePushMFARequest) returns (VerifyAndEnablePushMFAResponse)`
Enable push MFA after device registration.

#### `RegisterPushDevice(RegisterPushDeviceRequest) returns (RegisterPushDeviceResponse)`
Register additional device tokens.

#### `UnregisterPushDevice(UnregisterPushDeviceRequest) returns (UnregisterPushDeviceResponse)`
Remove device tokens.

#### `RespondToPushChallenge(RespondToPushChallengeRequest) returns (RespondToPushChallengeResponse)`
Handle push MFA challenge responses (approve/deny).

#### `GetPushChallengeStatus(GetPushChallengeStatusRequest) returns (GetPushChallengeStatusResponse)`
Check status of pending push challenges.

### MFA Challenge Management

#### `SendMFAChallenge(SendMFAChallengeRequest) returns (SendMFAChallengeResponse)`
Trigger MFA challenge based on user's configured method.
-   **Methods**: TOTP, HOTP, Email, Push
-   **Response**: Challenge details and user guidance

#### `VerifyMFAChallenge(VerifyMFAChallengeRequest) returns (VerifyMFAChallengeResponse)`
Validate MFA challenge response.

### Recovery & Security Management

#### `GenerateRecoveryCodes(GenerateRecoveryCodesRequest) returns (GenerateRecoveryCodesResponse)`
Generate new backup recovery codes.
-   **Security**: Requires re-authentication
-   **Process**: Invalidate old codes, generate new ones

#### `Disable2FA(Disable2FARequest) returns (google.protobuf.Empty)`
Disable all MFA for the account.
-   **Security**: Requires password or current MFA verification
-   **Process**: Clear all MFA settings and recovery codes

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

## Additional Services

### PhoneVerificationService

SMS-based phone number verification for enhanced security.

#### `SendVerificationOTP(SendVerificationOTPRequest) returns (SendVerificationOTPResponse)`
Send SMS OTP for phone verification.

#### `VerifyPhoneNumber(VerifyPhoneNumberRequest) returns (VerifyPhoneNumberResponse)`
Validate phone number with OTP code.

### MFAService (Email MFA)

Email-based multi-factor authentication.

#### `InitiateEmailMFASetup(InitiateEmailMFASetupRequest) returns (InitiateEmailMFASetupResponse)`
Start email MFA configuration.

#### `VerifyAndEnableEmailMFA(VerifyAndEnableEmailMFARequest) returns (VerifyAndEnableEmailMFAResponse)`
Complete email MFA setup.

#### `SendMFAChallenge(SendMFAChallengeRequest) returns (SendMFAChallengeResponse)`
Send email-based MFA challenge.

#### `VerifyMFAChallenge(VerifyMFAChallengeRequest) returns (VerifyMFAChallengeResponse)`
Verify email MFA response.

### PushMFAService

Firebase-powered push notification MFA management.

#### `RegisterDeviceToken(RegisterDeviceTokenRequest) returns (RegisterDeviceTokenResponse)`
Register device for push notifications.

#### `CreatePushMFAChallenge(CreatePushMFAChallengeRequest) returns (CreatePushMFAChallengeResponse)`
Create push MFA challenge.

#### `VerifyPushMFAChallenge(VerifyPushMFAChallengeRequest) returns (VerifyPushMFAChallengeResponse)`
Verify push challenge response.

#### `EnablePushMFA(EnablePushMFARequest) returns (EnablePushMFAResponse)`
Enable push MFA for user.

#### `DisablePushMFA(DisablePushMFARequest) returns (DisablePushMFAResponse)`
Disable push MFA.

### FederationService

Cross-domain identity federation and external provider integration.

#### `AddIdentityProvider(AddIdentityProviderRequest) returns (AddIdentityProviderResponse)`
Configure external identity provider.

#### `ListIdentityProviders(ListIdentityProvidersRequest) returns (ListIdentityProvidersResponse)`
List configured identity providers.

#### `UpdateIdentityProvider(UpdateIdentityProviderRequest) returns (UpdateIdentityProviderResponse)`
Modify identity provider configuration.

#### `DeleteIdentityProvider(DeleteIdentityProviderRequest) returns (DeleteIdentityProviderResponse)`
Remove identity provider.

---

## API Patterns & Best Practices

### Authentication Flow
1. **Primary Auth**: `Login` → returns tokens or MFA requirement
2. **MFA Verification**: `Verify2FA` → complete authentication
3. **Session Management**: `ListUserSessions`, `ClearUserSessions`

### User Registration Flow
1. **Registration**: `RegisterUser` → creates pending account
2. **Email Verification**: `SendEmailVerification` → `VerifyEmail`
3. **Account Activation**: `ActivateUser` → enables account

### Password Reset Flow
1. **Request Reset**: `RequestPasswordReset` → sends email
2. **Reset Password**: `ResetPassword` → validates token and updates

### MFA Setup Flow
1. **Initiate Setup**: Method-specific setup (TOTP, Email, Push)
2. **Verify Setup**: Complete verification and enable
3. **Generate Recovery**: Backup codes for account recovery

### Security Considerations
- All sensitive operations require authentication
- Password changes require current password verification
- MFA operations include rate limiting
- Audit logging on all security-relevant actions
- Token expiration and automatic cleanup

---

*Complete message structures and detailed field descriptions are available in the `.proto` files located in `proto/sso/v1/`.*
