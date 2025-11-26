# Shadow SSO (3SO): Your Go-Powered Identity Fortress 🛡️

**A Robust and Flexible OAuth 2.0 and OpenID Connect Implementation for Go**

<p align="center">
   <a href="https://github.com/pilab-dev/shadow-sso">
      <img src="https://img.shields.io/github/stars/pilab-dev/shadow-sso?style=social" alt="GitHub stars"></a>
   <a href="https://pkg.go.dev/github.com/pilab-dev/shadow-sso">
      <img src="https://pkg.go.dev/badge/github.com/pilab-dev/shadow-sso" alt="Go Reference">
   </a>
   <a href="https://github.com/pilab-dev/shadow-sso/blob/main/LICENSE">
      <img src="https://img.shields.io/github/license/pilab-dev/shadow-sso" alt="License">
   </a>
   <img src="https://github.com/pilab-dev/shadow-sso/workflows/Build, Test and Coverage/badge.svg" alt="Pipeline Status" title="Pipeline Status">
   <img src="https://codecov.io/github/pilab-dev/shadow-sso/branch/v1/graph/badge.svg?token=KWTJG0ADS0" alt="Coverage" title="Covrage"/>
</p>


Shadow SSO provides a complete suite of tools to implement secure authentication and authorization in your Go applications. We've crafted it with clarity and modularity, making it easier to protect your APIs and data. This package is compliant with industry standards, ensuring smooth integration with any client that also adheres to OAuth 2.0 and OIDC principles.

## Activity

![Activity](https://repobeats.axiom.co/api/embed/d3928fa3b3baa758e899f0e6924a65bc10622127.svg "Repobeats analytics image")

## ✨ Key Features

Shadow SSO is packed with comprehensive authentication functionality to ensure top-tier security and control:

### 🔐 Core Authentication
-   **⚙️ Full OAuth 2.0 Support (RFC 6749):** Complete implementation covering all necessary protocols
-   **🌐 OpenID Connect (OIDC) Support:** Secure user identification and profile access
-   **🔑 PKCE Support (RFC 7636):** Public client security via Proof Key for Code Exchange
-   **🧐 Token Introspection (RFC 7662):** Validate token validity and properties securely
-   **🚫 Token Revocation (RFC 7009):** Immediate session cancellation and threat response
-   **🔑 JWT Token Management:** Secure JWT-based access and refresh tokens with configurable TTL

### 🔐 Advanced Multi-Factor Authentication (MFA)
-   **📱 TOTP (Time-based One-Time Password):** Authenticator app integration (Google Authenticator, Authy, etc.)
-   **📧 Email-based MFA:** One-time passwords sent via email for authentication
-   **📱 Push Notification MFA:** Firebase-powered push notifications for mobile approval
-   **📞 SMS/Phone Verification:** Phone number verification with OTP codes
-   **🔄 Recovery Codes:** Backup authentication codes for account recovery
-   **🔐 HOTP Support:** HMAC-based one-time passwords for advanced use cases

### 👤 User Management & Lifecycle
-   **📝 User Registration:** Self-service user registration with email verification
-   **🔒 Account Activation:** Admin-controlled account activation workflow
-   **🚫 Account Locking:** Security-focused account suspension capabilities
-   **🔑 Password Management:** Secure password changes with old password verification
-   **📧 Password Reset:** Self-service password reset via email with secure tokens
-   **👤 Profile Management:** User profile editing and updates
-   **📱 Phone Number Management:** Phone number verification and updates

### 🖥️ Session & Security Management
-   **🕹️ Advanced Session Management:** Fine-grained session control and revocation
-   **🔍 Session Monitoring:** Real-time session tracking and audit capabilities
-   **🛡️ Security Audit Logging:** Comprehensive audit trails for all authentication events
-   **⏰ Account Lockout Protection:** Failed login attempt tracking and lockout
-   **📊 Metrics & Monitoring:** Built-in Prometheus metrics for monitoring

### 🤖 Client & API Management
-  **👥 OAuth2 Client Management:** Complete client registration and configuration
-   **🔐 Client Authentication:** Secure client credential validation
-   **🎯 Scope Management:** Granular permission and scope control
-   **🔄 Grant Types Support:**
    -   `authorization_code` - Industry standard for web applications
    -   `client_credentials` - Machine-to-machine authentication
    -   `resource_owner_password` - Direct user authorization
    -   `refresh_token` - Seamless token renewal

### 🏢 Enterprise Features
-   **🛡️ LDAP / Active Directory Integration:** External user authentication with attribute mapping
-   **🔗 Identity Provider Federation:** Support for external IdPs (OIDC, SAML)
-   **👨‍💼 Service Accounts:** Machine identities with downloadable JSON keys
-   **🏗️ Distributed Token Store (DTS):** High-performance BBoltDB-based token storage
-   **🐳 Kubernetes Integration:** Helm charts for production deployment

### 📱 Mobile & Modern UX
-   **📲 Firebase Push Notifications:** Native mobile push authentication
-   **🌐 External Login UI:** Next.js-based login interface support
-   **📊 Consent Management:** OAuth scope consent with detailed descriptions
-   **🔄 Real-time Status Updates:** Live MFA challenge status monitoring

## 🚀 Getting Started

Shadow SSO can be used as a standalone server application or as a library in your Go projects.

### 📦 Installation

To use Shadow SSO as a library:
```bash
go get github.com/pilab-dev/shadow-sso
```

To install the server application and CLI tool:
```bash
go install github.com/pilab-dev/shadow-sso/apps/ssso@latest
go install github.com/pilab-dev/shadow-sso/apps/ssoctl@latest
```
This will install `ssso` (the server) and `ssoctl` (the CLI) to your `$GOPATH/bin` directory.

### ‎️‍🔥 Running the SSO Server Application

The SSO server application is located in the `apps/ssso` directory.

1.  **Configuration:**
    The server is configured using Viper. It looks for a config file named `sso_config.yaml` (or `.json`, `.toml`, etc.) in the current directory, `/etc/sso/`, or `$HOME/.sso`.
    Alternatively, configuration can be provided via environment variables prefixed with `SSSO_`.

    Key configuration options (environment variables):

    ### Core Configuration
    -   `SSSO_HTTP_ADDR`: HTTP server address (default: `0.0.0.0:8080`)
    -   `SSSO_LOG_LEVEL`: Logging level - `debug`, `info`, `warn`, `error` (default: `info`)
    -   `SSSO_ISSUER_URL`: OIDC issuer URL for tokens (default: `http://localhost:8080`)

    ### Database Configuration
    -   `SSSO_MONGO_URI`: MongoDB connection URI (default: `mongodb://localhost:27017`)
    -   `SSSO_MONGO_DB_NAME`: MongoDB database name (default: `shadow_sso_db`)
    -   `SSSO_STORAGE_BACKEND`: Storage backend - `mongodb` or `dts` (default: `mongodb`)

    ### Security Configuration
    -   `SSSO_SIGNING_KEY_PATH`: RSA private key PEM file path for JWT signing (required)
    -   `SSSO_KEY_ROTATION_INTERVAL`: JWKS key rotation interval (default: `24h`)
    -   `SSSO_ACCESS_TOKEN_TTL`: Access token lifetime (default: `1h`)
    -   `SSSO_REFRESH_TOKEN_TTL`: Refresh token lifetime (default: `720h`)
    -   `SSSO_SECURITY_PASSWORD_HASH_COST`: Bcrypt cost factor (default: `12`)

    ### Distributed Token Store (DTS)
    -   `SSSO_DTS_CLIENT_ADDRESS`: DTS gRPC service address (default: `ssso-dts:50051`)
    -   `SSSO_DTS_TIMEOUT`: DTS connection timeout (default: `5s`)

    ### External Services Integration
    -   `SSSO_NEXTJS_LOGIN_URL`: External Next.js login UI URL

    ### Notification Services
    -   `SSSO_RESEND_API_KEY`: Resend API key for email notifications
    -   `SSSO_FROM_EMAIL`: Sender email address for outgoing emails
    -   `SSSO_NEXT_PUBLIC_BASE_URL`: Base URL for email verification links
    -   `SSSO_TWILIO_ACCOUNT_SID`: Twilio Account SID for SMS
    -   `SSSO_TWILIO_AUTH_TOKEN`: Twilio Auth Token for SMS
    -   `SSSO_TWILIO_PHONE_NUMBER`: Twilio phone number for sending SMS
    -   `SSSO_FIREBASE_PROJECT_ID`: Firebase project ID for push notifications
    -   `SSSO_FIREBASE_CREDENTIALS_PATH`: Path to Firebase service account credentials

    ### Initial Admin Setup
    -   `SSSO_INITIAL_ADMIN_ENABLED`: Enable automatic admin creation (default: `false`)
    -   `SSSO_INITIAL_ADMIN_EMAIL`: Initial admin email address
    -   `SSSO_INITIAL_ADMIN_PASSWORD`: Initial admin password (change immediately)
    -   `SSSO_INITIAL_ADMIN_FIRST_NAME`: Initial admin first name
    -   `SSSO_INITIAL_ADMIN_LAST_NAME`: Initial admin last name

    Example `sso_config.yaml`:
    ```yaml
    # Server Configuration
    http_addr: "0.0.0.0:8080"
    log_level: "info"
    issuer_url: "https://sso.example.com"

    # Database Configuration
    mongo_uri: "mongodb://user:pass@host:port/shadow_sso_db"
    mongo_db_name: "shadow_sso_db"
    storage_backend: "mongodb"  # or "dts" for Distributed Token Store

    # Security Configuration
    signing_key_path: "/etc/sso/keys/private.pem"
    key_rotation_interval: "24h"
    access_token_ttl: "1h"
    refresh_token_ttl: "720h"  # 30 days
    security_password_hash_cost: 12

    # Distributed Token Store (when using DTS)
    dts_client_address: "ssso-dts:50051"
    dts_timeout: "5s"

    # External Services
    nextjs_login_url: "https://login.example.com"

    # Notification Services
    resend_api_key: "your_resend_api_key"
    from_email: "noreply@yourdomain.com"
    next_public_base_url: "https://yourdomain.com"
    twilio_account_sid: "your_twilio_account_sid"
    twilio_auth_token: "your_twilio_auth_token"
    twilio_phone_number: "+1234567890"
    firebase_project_id: "your_firebase_project_id"
    firebase_credentials_path: "/etc/sso/firebase-credentials.json"

    # Initial Admin Setup
    initial_admin_enabled: false
    initial_admin_email: "admin@example.com"
    initial_admin_password: "change-me-immediately"
    initial_admin_first_name: "Admin"
    initial_admin_last_name: "User"
    ```

2.  **Running the server:**
    After installation, you can run the server directly:
    ```bash
    ssso
    ```
    Or, if building from source:
    ```bash
    cd apps/ssso
    go run . # Assuming main.go or ssso.go is in apps/ssso
    ```

### 🐳 Docker Deployment

Shadow SSO provides flexible Docker deployment options for different architectures:

#### Standard MongoDB Deployment
```bash
docker run -d \
  --name ssso-server \
  -p 8080:8080 \
  -e SSSO_MONGO_URI="mongodb://your_mongo_host:27017/shadow_sso_db" \
  -e SSSO_ISSUER_URL="http://localhost:8080" \
  -e SSSO_SIGNING_KEY_PATH="/path/to/your/signing_key.pem" \
  -e SSSO_FIREBASE_PROJECT_ID="your-firebase-project" \
  -e SSSO_FIREBASE_CREDENTIALS_PATH="/etc/sso/firebase/credentials.json" \
  -e SSSO_TWILIO_ACCOUNT_SID="your-twilio-sid" \
  -e SSSO_TWILIO_AUTH_TOKEN="your-twilio-token" \
  -e SSSO_TWILIO_PHONE_NUMBER="+1234567890" \
  -e SSSO_RESEND_API_KEY="your-resend-key" \
  -e SSSO_FROM_EMAIL="noreply@yourdomain.com" \
  -e SSSO_NEXT_PUBLIC_BASE_URL="https://yourdomain.com" \
  -v /path/to/keys:/etc/sso/keys:ro \
  -v /path/to/firebase-creds:/etc/sso/firebase:ro \
  pilab/ssso:latest
```

#### Distributed Token Store (DTS) Deployment
```bash
# Start MongoDB
docker run -d --name mongodb -p 27017:27017 mongo:latest

# Start DTS service
docker run -d --name ssso-dts -p 50051:50051 pilab/ssso-dts:latest

# Start SSO server with DTS
docker run -d \
  --name ssso-server \
  -p 8080:8080 \
  --link ssso-dts \
  -e SSSO_STORAGE_BACKEND="dts" \
  -e SSSO_DTS_CLIENT_ADDRESS="ssso-dts:50051" \
  -e SSSO_MONGO_URI="mongodb://mongodb:27017/shadow_sso_db" \
  -e SSSO_ISSUER_URL="http://localhost:8080" \
  pilab/ssso:latest
```

### 🚀 Initial Admin User Setup

On first startup, Shadow SSO can automatically create an initial administrator user if no admin users exist in the database.

**Helm Configuration:**
```yaml
initialAdmin:
  enabled: true
  credentials:
    email: admin@example.com
    password: "secure-password-change-me"
    firstName: "Admin"
    lastName: "User"
```

**Environment Variables:**
- `SSSO_INITIAL_ADMIN_ENABLED=true`
- `SSSO_INITIAL_ADMIN_EMAIL=admin@example.com`
- `SSSO_INITIAL_ADMIN_PASSWORD=secure-password`

## ✨ Distributed Token Store (DTS) Architecture

Shadow SSO features a high-performance distributed architecture with specialized storage backends:

### 🏗️ Architecture Components

*   **`ssso-dts` Service**: High-performance gRPC microservice using BBoltDB for ephemeral token storage
*   **MongoDB Integration**: Persistent storage for user profiles, clients, and service accounts
*   **Hybrid Storage Model**: Optimal performance with specialized storage for different data types

### 🚀 Performance Benefits

- **⚡ Sub-millisecond Token Operations**: BBoltDB provides extremely fast key-value operations
- **📈 Horizontal Scalability**: Distributed token storage across multiple DTS instances
- **💾 Reduced MongoDB Load**: Ephemeral OAuth artifacts separated from persistent user data
- **🔄 Automatic Cleanup**: Built-in token expiration and cleanup mechanisms

### 🐳 Production Deployment

#### Docker Compose Setup
```bash
docker-compose up --build
```

This deploys:
- **MongoDB**: User data and configurations (port 27017)
- **ssso-dts**: Distributed token store (port 50051)
- **ssso**: Main authentication service (port 8080)

#### Kubernetes with Helm
```bash
helm install ssso-backend ./helm/ssso-backend
```

Includes:
- **Configurable Storage Backends**: MongoDB or DTS options
- **High Availability**: Multi-replica deployments
- **Auto-scaling**: Horizontal Pod Autoscaling support
- **Security**: Network policies and RBAC integration

### ⚙️ Configuration Options

**DTS Configuration:**
```yaml
storage_backend: dts
dts_client_address: ssso-dts:50051
dts_timeout: 5s
```

**MongoDB Configuration:**
```yaml
mongo_uri: mongodb://user:pass@host:27017/shadow_sso_db
mongo_db_name: shadow_sso_db
```

###  CLI Tool (`ssoctl`)

The `ssoctl` CLI tool helps manage your Shadow SSO instance. It's located in `apps/ssoctl`.

1.  **Configuration:**
    `ssoctl` manages its configuration, including server endpoints and authentication tokens, in a file typically located at `$HOME/.ssoctl/config.yaml`.

2.  **Basic Usage:**
    Use `ssoctl --help` to see available commands.
    A common first step is to configure a context for your SSO server:
    ```bash
    ssoctl config set-context my-sso --server https://sso.example.com
    ssoctl config use-context my-sso
    ```
    Then you can log in:
    ```bash
    ssoctl auth login
    ```
    And interact with the server:
    ```bash
    ssoctl user list
    ssoctl client list
    ```

### 📚 Using Shadow SSO as a Library

Shadow SSO can be embedded into your Go applications as a library with comprehensive service providers:

#### Basic Setup with Service Providers

```go
package main

import (
    "log"
    "net/http"
    "time"

    "github.com/pilab-dev/shadow-sso/api"
    "github.com/pilab-dev/shadow-sso/cache"
    "github.com/pilab-dev/shadow-sso/mongodb"
    "github.com/pilab-dev/shadow-sso/services"
    "github.com/pilab-dev/shadow-sso/internal/oidcflow"
)

func main() {
    // 1. Configure OpenID Provider
    oidcConfig := &api.OpenIDProviderConfig{
        Issuer:             "http://localhost:8080",
        HTTPAddr:           "0.0.0.0:8080",
        AccessTokenTTL:     1 * time.Hour,
        RefreshTokenTTL:    30 * 24 * time.Hour,
        NextJSLoginURL:     "http://localhost:3000/login",
    }

    // 2. Initialize MongoDB repository provider
    mongoURI := "mongodb://localhost:27017"
    dbName := "shadow_sso"
    repoProvider, err := mongodb.NewMongoRepositoryProvider(mongoURI, dbName)
    if err != nil {
        log.Fatalf("Failed to initialize MongoDB: %v", err)
    }

    // 3. Create service provider with all dependencies
    serviceProvider, err := services.NewDefaultServiceProvider(services.DefaultServiceProviderOptions{
        RepositoryProvider: repoProvider,
        Config:            oidcConfig,
        FlowStore:         oidcflow.NewInMemoryFlowStore(),
        UserSessionStore:  oidcflow.NewInMemoryUserSessionStore(),
    })
    if err != nil {
        log.Fatalf("Failed to initialize services: %v", err)
    }

    // 4. Start gRPC server with all services
    server := &connectrpc.Server{
        AuthService:         services.NewAuthServer(serviceProvider),
        UserService:         serviceProvider.UserService(),
        TwoFactorService:    serviceProvider.TwoFactorService(),
        ClientManagementService: serviceProvider.ClientService(),
        // ... other services
    }

    log.Println("SSO server starting on :8080")
    if err := http.ListenAndServe(":8080", server.Router()); err != nil {
        log.Fatalf("Server failed: %v", err)
    }
}
```

#### Advanced Configuration with External Services

```go
// Configure external services for enhanced functionality
serviceProviderOpts := services.DefaultServiceProviderOptions{
    RepositoryProvider: repoProvider,
    Config:            oidcConfig,
    // Add Firebase for push notifications
    PushNotificationService: notifications.NewFirebasePushService(
        "your-firebase-project",
        "/path/to/firebase-credentials.json",
    ),
    // Add Twilio for SMS
    SMSService: notifications.NewTwilioSMSService(
        "your-twilio-sid",
        "your-twilio-token",
    ),
    // Add Resend for email
    EmailService: notifications.NewResendEmailService(
        "your-resend-api-key",
    ),
}
```

Our goal with Shadow SSO is not only powerful functionality but also unmatched security. For your trust, it comes with these implemented practices:

### 🔒 Security-First Design
- **⏱️ Constant-time Comparisons**: All sensitive data comparisons (passwords, tokens, secrets) use timing-attack-resistant algorithms
- **🔑 PKCE by Default**: Public clients are mandated to use Proof Key for Code Exchange, preventing authorization code interception
- **🏦 Bcrypt Password Hashing**: Industry-standard password hashing with configurable cost factor
- **🔐 JWT Security**: Secure JWT token generation with proper signing and configurable expiration

### 🛡️ Advanced Security Features
- **🔍 Comprehensive Audit Logging**: Every authentication event is logged with detailed context for security monitoring
- **🚫 Account Lockout Protection**: Configurable failed login attempt tracking with automatic account suspension
- **⏰ Session Expiry Management**: Automatic session invalidation with configurable timeouts
- **🔄 Secure Token Rotation**: Support for refresh token rotation to prevent token replay attacks
- **📱 Device-based Security**: Push MFA with device registration and challenge-response authentication

### ✅ Authorization & Access Control
- **👮 RBAC Integration**: Role-Based Access Control with configurable permissions
- **🎯 Granular Scope Validation**: Every OAuth scope is validated and unauthorized permissions are blocked
- **🤖 Client Authentication**: Multi-level client verification (confidential vs public clients)
- **🔎 Token Introspection**: Real-time token validation with detailed metadata exposure control
- **📊 Security Metrics**: Prometheus metrics for monitoring authentication patterns and anomalies

## ⚙️ Configuration Reference

Shadow SSO provides extensive configuration options through the `api.OpenIDProviderConfig` struct:

### Core OIDC Configuration

```go
config := &api.OpenIDProviderConfig{
    // Server Settings
    Issuer:      "https://sso.example.com",
    HTTPAddr:    "0.0.0.0:8080",
    LogLevel:    "info",

    // Token Configuration
    AccessTokenTTL:  1 * time.Hour,
    RefreshTokenTTL: 30 * 24 * time.Hour,

    // Security Settings
    SecurityConfig: api.SecurityConfig{
        PasswordHashingCost: 12,
        RequirePKCE:         true,
    },

    // External UI Integration
    NextJSLoginURL: "https://login.example.com",

    // Database Settings
    MongoURI:    "mongodb://localhost:27017",
    MongoDBName: "shadow_sso_db",
    StorageBackend: "mongodb", // or "dts"
}
```

### Distributed Token Store Configuration

```go
// For DTS backend
config.StorageBackend = "dts"
config.DTSClientAddress = "ssso-dts:50051"
config.DTSTimeout = 5 * time.Second
```

### External Service Integration

```go
// Firebase for push notifications
pushService := notifications.NewFirebasePushService(
    "your-project-id",
    "/etc/sso/firebase-credentials.json",
)

// Twilio for SMS
smsService := notifications.NewTwilioSMSService(
    "your-account-sid",
    "your-auth-token",
)

// Resend for email
emailService := notifications.NewResendEmailService(
    "your-api-key",
)
```

## 🌊 OIDC Authentication Flow with Separate UI

Shadow SSO supports modern OIDC authentication flows with separate frontend UI integration:

1.  **Authorization Request**: User redirected to `/oauth2/authorize` endpoint
2.  **UI Delegation**: Redirected to configured Next.js login UI with secure `flowId`
3.  **Authentication**: Frontend UI handles user login with full MFA support
4.  **Token Generation**: Backend validates credentials and generates authorization codes
5.  **Callback**: User redirected back to relying party with authorization code

### 📱 Mobile-First Authentication
- **Push Notifications**: Firebase-powered mobile push authentication
- **App Integration**: Native mobile app support with device registration
- **Real-time Updates**: Live MFA challenge status monitoring
- **Offline Support**: Recovery codes for offline authentication scenarios

For detailed frontend integration instructions, see `README_FRONTEND.md`.

## 🧩 Repository Interfaces

Shadow SSO uses a modular architecture with well-defined interfaces for data persistence. The current implementation provides MongoDB and in-memory implementations:

### Core Repository Interfaces

-   **`UserRepository`**: User account management, authentication, and profile data
-   **`SessionRepository`**: User session tracking and management
-   **`ClientRepository`**: OAuth2 client application configuration
-   **`TokenRepository`**: JWT token storage and management
-   **`AuthorizationCodeRepository`**: OAuth2 authorization code storage
-   **`DeviceAuthorizationRepository`**: OAuth2 device flow state management

### Advanced Repository Interfaces

-   **`FlowStore`**: OIDC flow state management (in-memory or persistent)
-   **`UserSessionStore`**: User session state for OIDC flows
-   **`PkceRepository`**: PKCE challenge storage
-   **`PublicKeyRepository`**: JWKS key management
-   **`ServiceAccountRepository`**: Machine identity management

### External Service Interfaces

-   **`PushNotificationService`**: Firebase push notification delivery
-   **`SMSService`**: SMS OTP delivery (Twilio integration)
-   **`EmailService`**: Email delivery (Resend integration)
-   **`MFAService`**: Multi-factor authentication orchestration
-   **`PhoneVerificationService`**: Phone number verification logic

### Implementing Custom Repositories

```go
// Example: Custom User Repository
type CustomUserRepository struct {
    db *sql.DB
}

func (r *CustomUserRepository) GetUserByID(ctx context.Context, id string) (*domain.User, error) {
    // Your implementation
}

func (r *CustomUserRepository) GetUserByEmail(ctx context.Context, email string) (*domain.User, error) {
    // Your implementation
}

// Implement remaining UserRepository methods...
```

All interfaces are defined in `domain/repositories.go` with comprehensive documentation.

## ⚠️ Standardized Error Handling

This package adopts the best practices when reporting errors during processes. In the package `/errors` directory all the implementation can be found and should be a good starting point for implement your project:

```go
    if err := validateRequest(); err != nil {
	    return errors.NewInvalidRequest("Invalid request parameters")
    }
```

## ❤️ Contributing

We appreciate any form of contribution! Please take time to follow the rules on the official guidelines, you are always welcomed: **https://github.com/pilab-dev/shadow-sso/blob/v1/.github/CONTRIBUTING.md**.

## 📜 License

Shadow SSO is released under the MIT License, giving you full freedom on utilizing, sharing, changing, and distributing with all other parties (check license files for all the details).

## Contact 📞

If any doubt, send a direct email message to `gyula@pilab.hu` or join our public Discord channel by requesting invite on same email.

---

This updated README provides a clearer structure, utilizes visuals, and offers a more comprehensive explanation of Shadow SSO's features, usage, and security considerations. It's designed to be more engaging and helpful for potential users and contributors.

---

## 📚 Documentation

- **[API Documentation](docs/api.md)**: Comprehensive gRPC service reference
- **[CLI Documentation](docs/cli.md)**: Command-line interface usage guide
- **[Federation Setup](docs/federation.md)**: External identity provider integration
- **[LDAP Setup](docs/ldap_setup.md)**: Active Directory integration guide
- **[Service Accounts](docs/service_accounts_usage.md)**: Machine identity management

## 🔄 Recent Updates

### ✅ Implemented Features
- **🔐 Advanced MFA**: Push notifications via Firebase, TOTP, HOTP, Email MFA
- **📱 Phone Verification**: SMS OTP verification for phone numbers
- **🔑 Password Reset**: Secure self-service password reset with email tokens
- **👤 User Registration**: Complete user lifecycle management
- **📊 Distributed Token Store**: High-performance BBoltDB backend for tokens
- **🔍 Comprehensive Audit**: Full audit logging for security compliance

### 🚧 In Development
- **🔄 Refresh Token Rotation**: Enhanced token security
- **📤 Back-channel Logout**: OIDC session management
- **🔐 Private Key JWT**: Advanced client authentication
- **🛡️ Rate Limiting**: Brute-force protection
- **📊 SAML Support**: Additional federation protocol

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](.github/CONTRIBUTING.md) for details on:
- Code style and standards
- Testing requirements
- Pull request process
- Development setup
