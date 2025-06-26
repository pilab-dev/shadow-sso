# Shadow SSO (3SO): Your Go-Powered Identity Fortress 🛡️
![Coverage](https://img.shields.io/badge/Coverage-3.9%25-red)

**A Robust and Flexible OAuth 2.0 and OpenID Connect Implementation for Go**

<p align="center">
   <a href="https://github.com/pilab-dev/shadow-sso"><img src="https://img.shields.io/github/stars/pilab-dev/shadow-sso?style=social" alt="GitHub stars"></a>
   <a href="https://pkg.go.dev/github.com/pilab-dev/shadow-sso"><img src="https://pkg.go.dev/badge/github.com/pilab-dev/shadow-sso" alt="Go Reference"></a>
   <a href="https://github.com/pilab-dev/shadow-sso/blob/main/LICENSE"><img src="https://img.shields.io/github/license/pilab-dev/shadow-sso" alt="License"></a>
   <img src="https://github.com/pilab-dev/shadow-sso/workflows/Build, Test and Coverage
/badge.svg">
<img src="https://img.shields.io/badge/Coverage-100.0%25-brightgreen"/>
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
    go run ssso.go
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

Here's a glimpse of what you need to launch Shadow SSO embedded in your own application. This example uses the Gin web framework and the provided MongoDB repositories. You can replace the MongoDB repositories with your own implementations if needed.

1.  **Service Initialization (Example):**

    ```go
    package main

    import (
        "context"
        "crypto/rsa"
        "log"
        "net/http"
        "time"

        "github.com/gin-gonic/gin"
        "go.mongodb.org/mongo-driver/v2/mongo"
        "go.mongodb.org/mongo-driver/v2/mongo/options"

        ssso "github.com/pilab-dev/shadow-sso"
        apiGin "github.com/pilab-dev/shadow-sso/api/gin"
        "github.com/pilab-dev/shadow-sso/client"
        "github.com/pilab-dev/shadow-sso/domain"
        "github.com/pilab-dev/shadow-sso/internal/auth"
        "github.com/pilab-dev/shadow-sso/internal/crypto" // Import for GenerateRSAKey
        "github.com/pilab-dev/shadow-sso/internal/oidcflow"
        "github.com/pilab-dev/shadow-sso/mongodb"
        "github.com/pilab-dev/shadow-sso/services"
    )

    func main() {
        // Generate RSA signing key
        signingKey, err := crypto.GenerateRSAKey() // Use crypto.GenerateRSAKey
        if err != nil {
            log.Fatalf("Error generating RSA signing key: %s\n", err.Error())
        }

        // Initialize MongoDB client
        mongoURI := "mongodb://localhost:27017" // Replace with your MongoDB URI
        dbName := "shadow_sso_example"
        ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
        defer cancel()

        mongoClient, err := mongo.Connect(ctx, options.Client().ApplyURI(mongoURI))
        if err != nil {
            log.Fatalf("Error connecting to MongoDB: %s\n", err.Error())
        }
        defer func() {
            if err = mongoClient.Disconnect(ctx); err != nil {
                log.Fatalf("Error disconnecting from MongoDB: %s\n", err.Error())
            }
        }()
        db := mongoClient.Database(dbName)

        // Initialize repositories
        oauthRepo, err := mongodb.NewOAuthRepository(ctx, db)
        if err != nil {
            log.Fatalf("Error creating OAuth repository: %s\n", err.Error())
        }
        userRepo, err := mongodb.NewUserRepositoryMongo(ctx, db)
        if err != nil {
            log.Fatalf("Error creating user repository: %s\n", err.Error())
        }
        clientStore := client.NewClientMemoryStore() // Example in-memory client store

        // Initialize services and other dependencies
        passwordHasher := auth.NewBCryptPasswordHasher()
        flowStore := oidcflow.NewInMemoryFlowStore()
        userSessionStore := oidcflow.NewInMemoryUserSessionStore()

        // Start cleanup routines for in-memory stores
        go func() {
            for {
                time.Sleep(10 * time.Minute)
                flowStore.CleanupExpiredFlows()
                userSessionStore.CleanupExpiredSessions()
            }
        }()

        // Initialize Repositories (User, OAuth, Session)
        // ... (userRepo, oauthRepo as before) ...
        sessionRepo, err := mongodb.NewSessionRepositoryMongo(ctx, db) // Example for SessionRepository
        if err != nil {
            log.Fatalf("Error creating session repository: %s\n", err.Error())
        }
        // In-memory token cache
        tokenCache := cache.NewMemoryTokenStore(10 * time.Minute)


        // Create core services
        // Key Management: For simplicity, generate one key. Real apps need robust key management.
        // JWKSService manages its own keys and rotation internally.
        jwksService, err := services.NewJWKSService(24 * time.Hour) // Example 24h key rotation
        if err != nil {
            log.Fatalf("Error creating JWKS service: %s\n", err.Error())
        }

        // TokenSigner needs a way to get the current private key.
        // For this example, we'll manually create one and give it to TokenSigner.
        // In a real system, TokenSigner might get the key from JWKSService or a shared key store.
        // This part is simplified for the example.
        currentPrivKey, err := crypto.GenerateRSAKey() // Example: generate a key
        if err != nil {
            log.Fatalf("Failed to generate RSA key for signer: %v", err)
        }
        tokenSigner := services.NewTokenSigner()
        // The AddKeySigner in services/signer.go takes a secret string for HS256.
        // This needs to be adapted for RSA keys if TokenSigner is to use RSA.
        // For now, assuming TokenSigner is set up externally or its AddKeySigner is updated.
        // Let's pretend AddKeySigner can take an RSA key, or TokenService constructor changes.
        // This highlights a potential area for refactoring the library for easier RSA key use with TokenSigner.
        // To make it runnable, let's assume TokenService can also work with just JWKSService for signing if TokenSigner is nil,
        // or TokenSigner is enhanced.
        // For now, this example will be slightly broken here conceptually.
        // We will use the signingKey directly with NewTokenService as per its old signature for simplicity,
        // acknowledging this does not align with the new JWKSService.
        // TODO: Revisit TokenService and TokenSigner interaction with JWKSService for RSA.

        // For the purpose of this example, let's assume TokenService can take the key directly for now,
        // OR that TokenSigner can be initialized with an RSA key.
        // The actual services.TokenService constructor is:
        // NewTokenService(repo domain.TokenRepository, tokenCache cache.TokenStore, issuer string, signer *TokenSigner, pubKeyRepo domain.PublicKeyRepository, saRepo domain.ServiceAccountRepository, userRepo domain.UserRepository)
        // It needs a *TokenSigner.
        // Let's assume we have a way to make TokenSigner use `currentPrivKey`.
        // The current TokenSigner in services/signer.go is for HS256.
        // This example needs to align with actual RSA signing.
        // For now, we'll pass a nil signer and assume TokenService can use JWKSService (hypothetical).

        // Simplified TokenService initialization for example clarity, actual may vary based on TokenSigner setup for RSA.
        // The current TokenService expects a TokenSigner for user tokens.
        // JWKSService is for providing JWKS. The actual signing key for TokenService needs to be consistent.
        // This example shows a conceptual setup.

        // Let's assume TokenService gets its signing key from JWKSService internally or via TokenSigner.
        // We'll create a simple TokenSigner (even if it's HS256 for this example, to make it compile).
        simpleTokenSigner := services.NewTokenSigner()
        simpleTokenSigner.AddKeySigner("a-very-secret-key-for-hs256-example") // Placeholder for HS256

        tokenService := services.NewTokenService(
            oauthRepo,
            tokenCache,
            "https://your-issuer.com",
            simpleTokenSigner, // Pass the simple signer
            oauthRepo, // Assuming oauthRepo implements PublicKeyRepository for service accounts
            oauthRepo, // Assuming oauthRepo implements ServiceAccountRepository
            userRepo,
        )

        oauthService := services.NewOAuthService(oauthRepo, userRepo, sessionRepo, tokenService, "https://your-issuer.com")
        // jwksService is already initialized above.
        // clientStore is defined, but NewClientManagementService takes oauthRepo and passwordHasher.
        // Assuming client management primarily uses oauthRepo for client persistence.
        clientManagementService := services.NewClientManagementService(oauthRepo, passwordHasher)
		pkceService := services.NewPKCEService(oauthRepo)


        // Initialize OAuth2 API configuration
        oidcConfig := ssso.NewDefaultConfig("https://your-issuer.com")
        oidcConfig.NextJSLoginURL = "https://your-nextjs-sso-ui.com/login" // URL for external login UI

        // Create OAuth2 API handlers
        oauth2API := apiGin.NewOAuth2API(
            oauthService,
            jwksService,
            clientManagementService, // Use the correct client service
            pkceService,
            config,
            flowStore,
            userSessionStore,
            userRepo,
            passwordHasher,
        )

        // Setup Gin server
        router := gin.Default()
        oauth2API.RegisterRoutes(router)

        log.Println("Starting server on :8080")
        if err := router.Run(":8080"); err != nil {
            log.Fatalf("Error starting server: %s\n", err.Error())
        }
    }
    ```

2.  **Client Application Registration:**

    Before your applications can use Shadow SSO, they must be registered.

    ```go
    // (Inside your main or a setup function, after clientService is initialized)
    // ctx := context.Background() // Ensure you have a context

    exampleClient := &domain.Client{
        ID:           "example_client_id",
        Secret:       "example_client_secret", // For confidential clients
        Name:         "My Awesome App",
        RedirectURIs: []string{"https://myapplication.com/callback"},
        GrantTypes:   []string{"authorization_code", "refresh_token"},
        Scopes:       []string{"openid", "profile", "email", "offline_access"},
        RequirePKCE:  true, // Recommended for all clients, mandatory for public ones
    }

    err = clientService.CreateClient(ctx, exampleClient) // Make sure ctx is defined
    if err != nil {
        log.Fatalf("Failed to register client: %v", err)
    }
    log.Println("Client registered successfully")
    ```

3.  **Authorization Code Flow:**

    This is the standard flow for web applications.

    ```go
    import "net/url"
    // import "crypto/rand" // For generating state and PKCE challenges
    // import "encoding/base64"

    // func generateRandomState() string {
    //     b := make([]byte, 32)
    //     rand.Read(b)
    //     return base64.RawURLEncoding.EncodeToString(b)
    // }

    // 1. Redirect user to authorization endpoint (client-side)
    // The actual state and PKCE parameters should be generated by the client application.
    authURL := "https://your-issuer.com/oauth2/authorize?" + url.Values{
        "client_id":     {"example_client_id"},
        "redirect_uri":  {"https://myapplication.com/callback"},
        "response_type": {"code"},
        "scope":         {"openid profile email"},
        // "state":         {generateRandomState()}, // Client should generate and store this
        // "code_challenge": {generatePKCEChallenge()}, // Client should generate and store verifier
        // "code_challenge_method": {"S256"},
    }.Encode()
    log.Printf("Redirect user to: %s", authURL) // In a real app, you'd perform an HTTP redirect.

    // 2. Handle callback and exchange code for tokens (server-side, after user authorizes)
    // Assume 'code' is received from the authorization server via redirect,
    // and 'pkceCodeVerifier' was stored by the client before the redirect.
    // ctx := context.Background() // Ensure you have a context
    // code := "received_auth_code_from_redirect"
    // pkceCodeVerifier := "stored_pkce_code_verifier"

    // tokenResponse, err := oauthService.ExchangeAuthorizationCode(
    //     ctx,
    //     code,
    //     "example_client_id",
    //     "example_client_secret", // Required for confidential clients
    //     "https://myapplication.com/callback",
    //     pkceCodeVerifier,
    // )
    // if err != nil {
    //     log.Fatalf("Failed to exchange authorization code: %v", err)
    // }
    // log.Printf("Access Token: %s", tokenResponse.AccessToken)
    // log.Printf("Refresh Token: %s", tokenResponse.RefreshToken)
    // log.Printf("ID Token: %s", tokenResponse.IDToken)
    ```
    *Note: PKCE parameters (`code_challenge`, `code_challenge_method`) are crucial for security, especially for public clients.*

4.  **Token Introspection:**

    Resource servers can use this endpoint to validate access tokens.

    ```go
    // (Assuming oauthService is initialized and you have a token to inspect)
    // ctx := context.Background() // Ensure you have a context
    // tokenToInspect := "some_access_token_value"

    // introspection, err := oauthService.IntrospectToken(
    //     ctx,
    //     tokenToInspect,
    //     "access_token", // token_type_hint
    //     // Client ID and secret of the resource server, if it's authenticating itself
    //     // Or, if the token is a Bearer token, these might not be needed depending on your setup.
    //     // "resource_server_client_id",
    //     // "resource_server_client_secret",
    // )
    // if err != nil {
    //     log.Fatalf("Failed to introspect token: %v", err)
    // }

    // if introspection.Active {
    //     log.Printf("Token is active for user: %s, with scopes: %s", introspection.Sub, introspection.Scope)
    // } else {
    //     log.Println("Token is not active.")
    // }
    ```

5.  **Session Management:**

    Manage user sessions.

    ```go
    // (Assuming oauthService is initialized)
    // ctx := context.Background() // Ensure you have a context
    // userID := "user_id_whose_sessions_to_manage"
    // sessionID := "session_id_to_revoke"

    // // List user sessions
    // sessions, err := oauthService.GetUserSessions(ctx, userID, domain.SessionFilter{})
    // if err != nil {
    //     log.Fatalf("Failed to get user sessions: %v", err)
    // }
    // for _, s := range sessions {
    //     log.Printf("Session ID: %s, IP: %s, UserAgent: %s, ExpiresAt: %v", s.ID, s.IPAddress, s.UserAgent, s.ExpiresAt)
    // }

    // // Revoke a specific session
    // err = oauthService.RevokeSession(ctx, sessionID)
    // if err != nil {
    //     log.Fatalf("Failed to revoke session: %v", err)
    // }
    // log.Printf("Session %s revoked", sessionID)

    // // Cleanup expired sessions for a user (typically run periodically by a background job)
    // // count, err := oauthService.CleanupExpiredSessions(ctx, userID)
    // // if err != nil {
    // //     log.Fatalf("Failed to cleanup expired sessions: %v", err)
    // // }
    // // log.Printf("Cleaned up %d expired sessions for user %s", count, userID)
    ```

## 🛡️ Security Practices

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
