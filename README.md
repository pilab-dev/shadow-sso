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

Shadow SSO is packed with essential functionality to ensure top-tier security and control over access:

-   **⚙️ Full OAuth 2.0 Support (RFC 6749):** Complete implementation covering all necessary protocols, allowing you to manage token lifecycles securely.
-   **🌐 OpenID Connect (OIDC) Support:** Secure user identification and profile access using OIDC extensions to OAuth 2.0, bringing trust and interoperability to the table.
-   **🔑 PKCE Support (RFC 7636):** Public client security via Proof Key for Code Exchange. This essential addition fortifies against Authorization Code interception threats.
-   **🧐 Token Introspection (RFC 7662):** Validate the validity and properties of tokens via a standardized mechanism that doesn't leak crucial information on every request.
-   **🚫 Token Revocation (RFC 7009):** Granting immediate cancellation of sessions and ensuring swift response to access threats.
-   **🔑 Session Management:** Efficient management of user session state.
-   **✅ Support for Multiple Grant Types:**
    -   `authorization_code` - Industry standard for web application login flow.
    -   `client_credentials` - For machine-to-machine authorizations.
    -   `resource_owner_password` - Direct user authorization to protect legacy apps.
    -   `refresh_token` - Seamless re-authentication without re-entering user credentials.
-   **🔒 Secure Token Handling:**  Ensures sensitive credentials and tokens are stored with encryption where needed, handled with precision, and safeguarded.
-  **👥 Client Application Management:** Control registration of clients in order to use and delegate your authentication server.
-   **🕹️ User Session Management:**  Fine grained access and revocation control over each individual session.
-   **🛡️ LDAP / Active Directory Integration:** Supports using external LDAP/AD servers as a user authentication source with per-client attribute mapping. See [LDAP Setup Guide](docs/ldap_setup.md).

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
    -   `SSSO_HTTP_ADDR`: Address for the HTTP server (e.g., `0.0.0.0:8080`). Default: `0.0.0.0:8080`.
    -   `SSSO_LOG_LEVEL`: Log level (e.g., `debug`, `info`, `warn`, `error`). Default: `info`.
    -   `SSSO_MONGO_URI`: MongoDB connection URI. Default: `mongodb://localhost:27017`.
    -   `SSSO_MONGO_DB_NAME`: MongoDB database name. Default: `shadow_sso_db`.
    -   `SSSO_ISSUER_URL`: The issuer URL for tokens. Default: `http://localhost:8080`.
    -   `SSSO_SIGNING_KEY_PATH`: Path to the RSA private key PEM file for signing tokens. (No default, must be provided or generated).
    -   `SSSO_KEY_ROTATION_INTERVAL`: Interval for JWKS key rotation (e.g., `24h`). Default: `24h`.
    -   `SSSO_NEXTJS_LOGIN_URL`: URL for the external Next.js login UI if using the separate UI flow.

    Example `sso_config.yaml`:
    ```yaml
    http_addr: "0.0.0.0:9090"
    log_level: "debug"
    mongo_uri: "mongodb://user:pass@host:port/mydb"
    mongo_db_name: "my_sso_database"
    issuer_url: "https://sso.example.com"
    signing_key_path: "/etc/sso/keys/private.pem"
    key_rotation_interval: "72h"
    nextjs_login_url: "https://login.example.com"
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

<<<<<<< HEAD
### 🐳 Running with Docker (Standard SSSO)

A `Dockerfile` is provided at the root of the project for the standard SSSO server.

1.  **Build the Docker image:**
    ```bash
    docker build -t pilab/ssso:latest .
    ```

2.  **Run the Docker container:**
    ```bash
    docker run -d \
      -p 8080:8080 \
      -e SSSO_MONGO_URI="mongodb://your_mongo_host:27017/shadow_sso_db" \
      -e SSSO_ISSUER_URL="http://localhost:8080" \
      -e SSSO_SIGNING_KEY_PATH="/path/to/your/signing_key.pem" \
      # Add other necessary SSSO_... environment variables
      # Potentially mount volumes for keys or persistent data if not using external Mongo
      --name ssso-server \
      pilab/ssso:latest
    ```

## ✨ Distributed Token Store (DTS) and SSSO-Alt Variant

To offer an alternative storage backend for improved performance and reduced dependency on MongoDB for ephemeral token data, Shadow SSO now includes:

*   **`ssso-dts` Service**: A gRPC service using BBoltDB for persistent, high-performance storage of session data, OIDC flows, and tokens. See `apps/ssso-dts/README.md` for details on this service.
*   **`ssso-alt` Service Variant**: An alternative version of the SSSO server (`apps/ssso-alt/`) that can be configured to use the `ssso-dts` service for storing specific OAuth/OIDC artifacts (like authorization codes, PKCE states, OIDC flow states, and refresh token details). Other data like user profiles, client configurations, and service account details still use MongoDB.

### 🚀 Running `ssso-alt` with `ssso-dts` using Docker Compose

The easiest way to run the `ssso-alt` variant along with its `ssso-dts` dependency and a MongoDB instance is using the provided `docker-compose.yml` file at the root of the project.

1.  **Prerequisites:**
    *   Docker and Docker Compose installed.

2.  **Build and Run:**
    Navigate to the root of the Shadow SSO project and run:
    ```bash
    docker-compose up --build
    ```
    This will:
    *   Build the Docker images for `ssso-dts` and `ssso-alt`.
    *   Start three services: `mongo`, `ssso-dts`, and `ssso-alt`.
    *   `ssso-dts` will listen on port `50051`.
    *   `ssso-alt` will listen on port `8081` (to avoid conflict with a standard `ssso` instance on `8080`).

3.  **Configuration for `ssso-alt`:**
    The `docker-compose.yml` file sets the necessary environment variables for `ssso-alt` to connect to `ssso-dts` and `mongo`. Key environment variables for `ssso-alt` include:
    *   `SSSO_ALT_STORAGE_BACKEND`: Set to `dts` to enable the Distributed Token Store. (Default is `mongodb` if not set, but compose file sets it to `dts`).
    *   `SSSO_DTS_CLIENT_ADDRESS`: Address of the `ssso-dts` gRPC service (e.g., `ssso-dts:50051` within the Docker network).
    *   Standard SSSO environment variables like `SSSO_MONGO_URI`, `SSSO_ISSUER_URL`, etc., are still required as `ssso-alt` uses MongoDB for non-DTS data.

    Refer to `apps/ssso-alt/config/config.go` and the `docker-compose.yml` for all configurable options.
=======
### 🚀 Initial Admin User Setup

On its first startup, the Shadow SSO server can automatically create an initial administrator user if no other admin users exist in the database. This is useful for bootstrapping a new deployment.

**Configuration:**

This feature is primarily configured via Helm when deploying to Kubernetes, or by setting specific environment variables if running the server binary directly.

**Helm Chart Configuration (`values.yaml`):**

Under the `initialAdmin` section in your `values.yaml` file:

*   `enabled`: (boolean, e.g., `true`) Set to `true` to enable this feature. If `false`, the server will not attempt to create an initial admin.
*   `createSecret`: (boolean, e.g., `true`) If `true`, Helm will create a Kubernetes Secret to store the initial admin credentials. If `false`, you must ensure a secret named by `secretName` already exists with the required data.
*   `secretName`: (string, e.g., `ssso-initial-admin-credentials`) The name of the Kubernetes Secret that holds (or will hold) the initial admin credentials.
*   `credentials`: A map containing:
    *   `email`: (string) The email address for the initial admin user.
    *   `password`: (string) The password for the initial admin user. **This must be changed from the default for any real deployment.**
    *   `firstName`: (string, optional) The first name for the admin user. Defaults to "Admin" if not provided or key is missing in secret.
    *   `lastName`: (string, optional) The last name for the admin user. Defaults to "User" if not provided or key is missing in secret.

**Environment Variables:**

The server application reads the following environment variables (which are typically populated from the Kubernetes Secret by the Helm chart):

*   `INITIAL_ADMIN_ENABLED`: Set to `"true"` to enable the feature.
*   `INITIAL_ADMIN_EMAIL`: Email for the first admin.
*   `INITIAL_ADMIN_PASSWORD`: Password for the first admin.
*   `INITIAL_ADMIN_FIRST_NAME`: (Optional) First name.
*   `INITIAL_ADMIN_LAST_NAME`: (Optional) Last name.

**Behavior:**

*   On startup, if `INITIAL_ADMIN_ENABLED` is `"true"`, the server checks if any users with the "admin" role exist.
*   If no admin users are found, it attempts to read the other `INITIAL_ADMIN_*` environment variables and create the user.
*   If an admin user already exists, or if the feature is not enabled, this setup step is skipped.
*   The server will log its actions regarding this setup process.

This ensures that your SSO system can be initialized with a primary administrator account without manual database intervention on the first run.
>>>>>>> 46dc357 (feat: Implement server-side initial admin user creation)

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

To embed Shadow SSO into your own Go application, you can now use the simplified `ssso.NewSSOServer` function. This function encapsulates the complex setup, allowing you to quickly get a fully configured OAuth 2.0 and OpenID Connect server.

1.  **Basic Setup (MongoDB and In-Memory Defaults):**

    This example shows how to set up an SSO server with a MongoDB backend and in-memory stores for OIDC flows and PKCE challenges, using default values where possible.

    ```go
    package main

    import (
        "context"
        "log"
        "net/http"
        "time"

        ssso "github.com/pilab-dev/shadow-sso"
    )

    func main() {
        // 1. Define your OpenID Provider Configuration
        // Start with sensible defaults and customize as needed.
        oidcConfig := ssso.NewDefaultConfig("http://localhost:8080")
        oidcConfig.NextJSLoginURL = "http://localhost:3000/login" // Example: integrate with an external login UI
        oidcConfig.AccessTokenTTL = 1 * time.Hour
        oidcConfig.RefreshTokenTTL = 24 * 30 * time.Hour // 30 days

        // 2. Initialize your Repository Provider (e.g., MongoDB)
        // You can use ssso.NewMongoRepositoryProvider for a MongoDB backend.
        // For production, ensure these values come from secure configuration.
        mongoURI := "mongodb://localhost:27017"
        dbName := "shadow_sso_example"
        repoProvider, err := ssso.NewMongoRepositoryProvider(mongoURI, dbName)
        if err != nil {
            log.Fatalf("Error initializing MongoDB repository provider: %v", err)
        }
        // For MongoDB-specific disconnection (e.g., if you need to call a Close method),
        // you might need to assert the concrete type if the ssso.RepositoryProvider interface
        // does not expose a Close/Disconnect method.
        // For example:
        // if mongoRp, ok := repoProvider.(*mongodb.MongoRepositoryProvider); ok { // Note: mongodb.MongoRepositoryProvider is the concrete type
        //     defer mongoRp.Disconnect(context.Background())
        // }
        // For simplicity in this example, deferring directly is omitted assuming the main app manages lifecycle.

        // 3. (Optional) Customize other components if defaults are not sufficient
        //    For example, a custom TokenSigner, TokenCache, or specific PkceRepository.
        //    If left nil, NewSSOServer will use sensible in-memory defaults.

        // 4. Create SSOServerOptions
        serverOpts := ssso.SSOServerOptions{
            Config:             oidcConfig,
            RepositoryProvider: repoProvider,
            // TokenSigner:        ssso.New...TokenSigner(), // Provide custom signer if needed (e.g., for RSA keys)
            // TokenCache:         ssso.New...TokenCache(),    // Provide custom cache if needed
            // PkceRepository:     ssso.New...PkceRepository(), // Provide custom PKCE repo if needed
            // FlowStore:          ssso.New...FlowStore(),      // Provide custom flow store if needed
            // UserSessionStore:   ssso.New...UserSessionStore(), // Provide custom user session store if needed
        }

        // 5. Initialize the SSO Server (Gin engine)
        router, err := ssso.NewSSOServer(serverOpts)
        if err != nil {
            log.Fatalf("Error initializing SSO server: %v", err)
        }

        // 6. Start the HTTP server
        addr := ":8080"
        log.Printf("SSO server starting on %s", addr)
        if err := http.ListenAndServe(addr, router); err != nil {
            log.Fatalf("SSO server failed to start: %v", err)
        }
    }
    ```

Our goal with Shadow SSO is not only powerful functionality but, also, unmatched security. For your trust, it comes with these implemented practices:

- **Constant-time Comparisons**: For sensitive data (like client secrets or authentication codes) we always use comparison methods that take same time regardless of differences to avoid timing attack possibilities.
-   **PKCE by Default**: Security is paramount, so public clients are mandated to use PKCE protocol by default, making man-in-the-middle attacks nearly impossible.
-   **Secure Token Storage**: You have all control and we give all control to ensure encryption when persisting data using repositories implementation, guaranteeing safe storing of all the token, user and client informations.
-   **Full-Spectrum Session Management:** Our session management approach allows full flexibility when using web and mobile client apps; you can audit user activity and selectively invalidate suspicious ones in response to suspicious requests and/or vulnerabilities discovered.
-   **Detailed Token Introspection**: Grant granular authorization using our `IntrospectToken` endpoint for each authorization access request coming from client app for APIs you are in charge to secure.
-   **Scope Validation**: Each scope requested on the `authorize` endpoint is validated and unauthorized permissions aren't assigned by our services.
-  **Client Authentication:** Authenticate any requesting app/client using credentials provided during registration before processing requests with endpoints, giving additional security check.

## ⚙️ Configuration

Customize Shadow SSO with fine-grained control. You are responsible of what configuration object to pass as configuration to your sso server instance during creation. All the configurable variables are presented in the `ssso.OpenIDProviderConfig` struct:

```go
    config := &ssso.OpenIDProviderConfig{
    Issuer:                "https://your-issuer.com",
        AuthorizationEndpoint: "https://your-issuer.com/oauth2/authorize",
        TokenEndpoint:         "https://your-issuer.com/oauth2/token",
        UserInfoEndpoint:      "https://your-issuer.com/oauth2/userinfo",
        JwksURI:              "https://your-issuer.com/.well-known/jwks.json",
        NextJSLoginURL:       "https://your-nextjs-sso-ui.com/login", // URL for external login UI
        // ... additional configuration
    }

	    oauth2API := sssogin.NewOAuth2API( // Assuming sssogin is the package for NewOAuth2API
		    oauthService,
		    jwksService,
		    clientService,
		    pkceService,
		    config,
            flowStore,          // New: OIDC flow state store
            userSessionStore,   // New: OP user session store
            userRepo,           // New: User repository (also used by OAuthService)
            passwordHasher,     // New: Password hasher
    	)
```

## 🌊 OIDC Authentication Flow with Separate UI

Shadow SSO now supports an OIDC authentication flow where the user authentication can be delegated to a separate frontend UI (e.g., a Next.js application).

1.  The user is redirected from the `/oauth2/authorize` endpoint to your configured `NextJSLoginURL` with a `flowId`.
2.  The frontend UI uses this `flowId` to fetch OIDC request details from `/api/oidc/flow/:flowId`.
3.  The user authenticates on the frontend UI.
4.  The frontend UI `POST`s the credentials and `flowId` to `/api/oidc/authenticate`.
5.  The Shadow SSO backend validates credentials, establishes an OP session (via cookie), generates an authorization code, and redirects the user back to the Relying Party.

For detailed instructions on frontend integration, see `README_FRONTEND.md`.

## 🧩 Essential Interface Implementation

You’re in the driver's seat on persisting the states. You will need to implement several interfaces.  This modular architecture grants the flexibility to incorporate it with your tech stack and specific security standards, if any are required. Implementations stubs are available within the `/interfaces` module of this repo.

-   **`OAuthRepository`:** Interface for persisting data like client registrations, authorization codes, access and refresh tokens, in your preferred method, from standard data store or specific cloud platform solution (check documentation folder for interfaces definition and stub samples).
-   **`UserRepository`:** Implements a persistent storage mechanism and manipulation method for sessions associated with a user during usage. (check documentation folder for interfaces definition and stub samples).
-  **`TokenStore`:** Implement this in case of memory usage problems and need some form of state management between access token introspection endpoints calls (Optional caching) (check documentation folder for interfaces definition and stub samples).

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

## TODO

- [ ] Implement refresh token rotation.
- [ ] Add support for more OIDC features (e.g., back-channel logout, front-channel logout).
- [ ] Enhance client authentication options (e.g., private_key_jwt).
- [ ] Improve documentation for advanced configuration and customization.
- [ ] Add more examples for different use cases and grant types.
- [ ] Implement a more robust solution for distributed session management.
- [ ] Add support for SAML.
- [ ] Implement rate limiting and brute-force protection.
- [ ] Add more comprehensive audit logging.
- [ ] Create a CLI for managing users, clients, and other aspects of the SSO.
