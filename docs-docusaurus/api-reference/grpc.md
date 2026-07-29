---
id: grpc
title: gRPC API
sidebar_label: gRPC API
---

# gRPC API Reference

Shadow SSO provides a comprehensive gRPC API for high-performance service-to-service communication.

## Overview

| Property | Value |
|----------|-------|
| Protocol | gRPC (HTTP/2) |
| Port | 8080 (shared with HTTP) |
| Auth | JWT Bearer Token |
| Format | Protocol Buffers |

## Services

### AuthService

Handles authentication, sessions, and OAuth2 flows.

#### Login

```protobuf
rpc Login(LoginRequest) returns (LoginResponse);
```

**Request:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `email` | string | Yes | User email |
| `password` | string | Yes | User password |

**Response:**

| Field | Type | Description |
|-------|------|-------------|
| `accessToken` | string | JWT access token |
| `refreshToken` | string | Refresh token |
| `tokenType` | string | Token type (Bearer) |
| `expiresIn` | int64 | Token TTL in seconds |
| `twoFactorRequired` | bool | MFA required |
| `twoFactorSessionToken` | string | MFA session token |

#### Verify2FA

```protobuf
rpc Verify2FA(Verify2FARequest) returns (LoginResponse);
```

**Request:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `userId` | string | Yes | User ID |
| `totpCode` | string | Conditional | TOTP code |
| `recoveryCode` | string | Conditional | Recovery code |
| `twoFactorSessionToken` | string | Yes | MFA session token |

#### Logout

```protobuf
rpc Logout(LogoutRequest) returns (google.protobuf.Empty);
```

#### RefreshToken

```protobuf
rpc RefreshToken(RefreshTokenRequest) returns (LoginResponse);
```

### UserService

User lifecycle management.

#### RegisterUser

```protobuf
rpc RegisterUser(RegisterUserRequest) returns (User);
```

**Request:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `email` | string | Yes | User email |
| `password` | string | Yes | User password |
| `firstName` | string | Yes | First name |
| `lastName` | string | Yes | Last name |

#### GetUser

```protobuf
rpc GetUser(GetUserRequest) returns (User);
```

#### ListUsers

```protobuf
rpc ListUsers(ListUsersRequest) returns (ListUsersResponse);
```

#### UpdateUser

```protobuf
rpc UpdateUser(UpdateUserRequest) returns (User);
```

#### DeleteUser

```protobuf
rpc DeleteUser(DeleteUserRequest) returns (google.protobuf.Empty);
```

#### ActivateUser

```protobuf
rpc ActivateUser(ActivateUserRequest) returns (User);
```

#### LockUser

```protobuf
rpc LockUser(LockUserRequest) returns (User);
```

#### ChangePassword

```protobuf
rpc ChangePassword(ChangePasswordRequest) returns (google.protobuf.Empty);
```

### ClientManagementService

OAuth2 client management.

#### RegisterClient

```protobuf
rpc RegisterClient(RegisterClientRequest) returns (Client);
```

**Request:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | Yes | Client name |
| `clientType` | string | Yes | `confidential` or `public` |
| `redirectUris` | []string | Yes | Allowed redirect URIs |
| `grantTypes` | []string | Yes | Allowed grant types |

#### GetClient

```protobuf
rpc GetClient(GetClientRequest) returns (Client);
```

#### ListClients

```protobuf
rpc ListClients(ListClientsRequest) returns (ListClientsResponse);
```

#### UpdateClient

```protobuf
rpc UpdateClient(UpdateClientRequest) returns (Client);
```

#### DeleteClient

```protobuf
rpc DeleteClient(DeleteClientRequest) returns (google.protobuf.Empty);
```

### TwoFactorService

Multi-factor authentication management.

#### SetupTOTP

```protobuf
rpc SetupTOTP(SetupTOTPRequest) returns (SetupTOTPResponse);
```

#### VerifyTOTP

```protobuf
rpc VerifyTOTP(VerifyTOTPRequest) returns (VerifyTOTPResponse);
```

#### Disable2FA

```protobuf
rpc Disable2FA(Disable2FARequest) returns (google.protobuf.Empty);
```

#### GenerateRecoveryCodes

```protobuf
rpc GenerateRecoveryCodes(GenerateRecoveryCodesRequest) returns (GenerateRecoveryCodesResponse);
```

### ServiceAccountService

Service account and machine identity management.

#### CreateServiceAccountKey

```protobuf
rpc CreateServiceAccountKey(CreateServiceAccountKeyRequest) returns (ServiceAccountKey);
```

#### ListServiceAccountKeys

```protobuf
rpc ListServiceAccountKeys(ListServiceAccountKeysRequest) returns (ListServiceAccountKeysResponse);
```

#### DeleteServiceAccountKey

```protobuf
rpc DeleteServiceAccountKey(DeleteServiceAccountKeyRequest) returns (google.protobuf.Empty);
```

### IdPManagementService

Identity provider management.

#### AddIdentityProvider

```protobuf
rpc AddIdentityProvider(AddIdentityProviderRequest) returns (IdentityProvider);
```

#### GetIdentityProvider

```protobuf
rpc GetIdentityProvider(GetIdentityProviderRequest) returns (IdentityProvider);
```

#### ListIdentityProviders

```protobuf
rpc ListIdentityProviders(ListIdentityProvidersRequest) returns (ListIdentityProvidersResponse);
```

#### UpdateIdentityProvider

```protobuf
rpc UpdateIdentityProvider(UpdateIdentityProviderRequest) returns (IdentityProvider);
```

#### DeleteIdentityProvider

```protobuf
rpc DeleteIdentityProvider(DeleteIdentityProviderRequest) returns (google.protobuf.Empty);
```

### FederationService

External identity provider federation.

#### InitiateFederation

```protobuf
rpc InitiateFederation(InitiateFederationRequest) returns (InitiateFederationResponse);
```

#### HandleFederationCallback

```protobuf
rpc HandleFederationCallback(HandleFederationCallbackRequest) returns (LoginResponse);
```

### PhoneVerificationService

Phone number verification.

#### SendPhoneVerificationCode

```protobuf
rpc SendPhoneVerificationCode(SendPhoneVerificationCodeRequest) returns (google.protobuf.Empty);
```

#### VerifyPhoneCode

```protobuf
rpc VerifyPhoneCode(VerifyPhoneCodeRequest) returns (google.protobuf.Empty);
```

### PushMFAService

Firebase push notification MFA.

#### RegisterDevice

```protobuf
rpc RegisterDevice(RegisterDeviceRequest) returns (google.protobuf.Empty);
```

#### SendPushChallenge

```protobuf
rpc SendPushChallenge(SendPushChallengeRequest) returns (google.protobuf.Empty);
```

#### RespondToChallenge

```protobuf
rpc RespondToChallenge(RespondToChallengeRequest) returns (LoginResponse);
```

## Authentication

All gRPC calls require JWT authentication:

```
metadata:
  authorization: Bearer <access-token>
```

## Error Codes

| gRPC Code | Description |
|-----------|-------------|
| `INVALID_ARGUMENT` | Invalid request parameters |
| `UNAUTHENTICATED` | Missing or invalid token |
| `PERMISSION_DENIED` | Insufficient permissions |
| `NOT_FOUND` | Resource not found |
| `ALREADY_EXISTS` | Resource already exists |
| `INTERNAL` | Internal server error |

## Protocol Buffer Definitions

Proto files are located in `proto/sso/v1/`:

```
proto/
├── sso/v1/
│   ├── auth_service.proto
│   ├── user_service.proto
│   ├── client_management_service.proto
│   ├── two_factor_service.proto
│   ├── service_account_service.proto
│   ├── idp_management_service.proto
│   ├── federation_service.proto
│   ├── phone_verification_service.proto
│   ├── push_mfa_service.proto
│   └── common.proto
```

## Code Generation

Generate client code for various languages:

```bash
# Install buf
make install-deps

# Generate code
make proto
```

### Go Client

```go
import (
    "context"
    
    "github.com/pilab-dev/shadow-sso/gen/proto/sso/v1/ssov1connect"
    "connectrpc.com/connect"
)

func main() {
    client := ssov1connect.NewAuthServiceClient(
        http.DefaultClient,
        "http://localhost:8080",
    )
    
    resp, err := client.Login(context.Background(), connect.NewRequest(&ssov1.LoginRequest{
        Email:    "user@example.com",
        Password: "password",
    }))
}
```

## Next Steps

- [GraphQL API](/api-reference/graphql) - Administrative API
- [CLI Reference](/api-reference/cli) - Command-line interface
