# Shadow SSO (3SO): Your Go-Powered Identity Fortress 🛡️

**A Robust and Flexible OAuth 2.0 and OpenID Connect Implementation for Go**

<p align="center">
   <a href="https://github.com/pilab-dev/shadow-sso"><img src="https://img.shields.io/github/stars/pilab-dev/shadow-sso?style=social" alt="GitHub stars"></a>
   <a href="https://pkg.go.dev/github.com/pilab-dev/shadow-sso"><img src="https://pkg.go.dev/badge/github.com/pilab-dev/shadow-sso" alt="Go Reference"></a>
   <a href="https://github.com/pilab-dev/shadow-sso/v1/blob/main/LICENSE"><img src="https://img.shields.io/github/license/pilab-dev/shadow-sso" alt="License"></a>
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

## 🚀 Getting Started

### 📦 Installation

```bash
go get github.com/pilab-dev/shadow-sso
```

### ⚡️ Quick Example

Here's a glimpse of what you need to launch Shadow SSO. Make sure that you fill your implementations for `NewYourOAuthRepository()` and `NewYourUserRepository()` methods with logic for persistance using for instance PostgresSQL, MySQL, SQLITE, Redis etc.:

1.  **Service Initialization:**

    ```go
    package main

    import (
        "github.com/labstack/echo/v4"
        ssso "github.com/pilab-dev/shadow-sso"
        "github.com/pilab-dev/shadow-sso/v1/client"
        "crypto/rsa"
        "log"
    )

    func main() {
      // Create a new key
	    signingKey, err := ssso.GenerateRSAKey()
	    if err != nil {
          log.Fatalf("error generating rsa signing key %s\n", err.Error())
      }

        // Initialize repositories
        oauthRepo := NewYourOAuthRepository() // Implement OAuthRepository interface
        userRepo := NewYourUserRepository()    // Implement UserRepository interface
        clientStore := client.NewClientMemoryStore()


        // Create services
        oauthService := ssso.NewOAuthService(oauthRepo, userRepo, signingKey, "https://your-issuer.com")
        jwksService := ssso.NewJWKSService(signingKey)
        clientService := client.NewClientService(clientStore)
		    pkceService := ssso.NewPKCEService(oauthRepo)

        // Initialize OAuth2 API
        config := ssso.NewDefaultConfig("https://your-issuer.com")
        oauth2API := ssso.NewOAuth2API(
            oauthService,
            jwksService,
            clientService,
            pkceService,
            config,
        )

        // Setup Echo server
        e := echo.New()
        oauth2API.RegisterRoutes(e)
        e.Logger.Fatal(e.Start(":8080"))
    }

    func loadSigningKey() *rsa.PrivateKey {
        // load RSA from persisted value. Generate otherwise
	    key, err := ssso.GenerateRSAKey()
        if err != nil {
        	panic(err)
        }
	    return key
    }
    ```

2.  **Client Application Registration:**

    ```go
	    client := &ssso.Client{
		    ID:           "client_id",
		    Secret:       "client_secret",
		    Name:         "Example App",
		    RedirectURIs: []string{"https://example.com/callback"},
		    GrantTypes:   []string{"authorization_code", "refresh_token"},
		    Scopes:       []string{"openid", "profile", "email"},
		    RequirePKCE:  true,
	    }
    err := clientService.CreateClient(client)
        if err != nil {
            panic(err)
    }

    ```

3.  **Authorization Code Flow:**

    ```go
	import "net/url"
	// 1. Redirect user to authorization endpoint
        authURL := "https://your-issuer.com/oauth2/authorize?" + url.Values{
            "client_id":     {"client_id"},
            "redirect_uri":  {"https://example.com/callback"},
            "response_type": {"code"},
            "scope":         {"openid profile"},
            "state":         {generateRandomState()},
        }.Encode()

	    // 2. Handle callback and exchange code for tokens
	    code := "received_auth_code"
        tokenResponse, err := oauthService.ExchangeAuthorizationCode(
            code,
            "client_id",
            "client_secret",
            "https://example.com/callback",
	    )

	    // now you have access to the tokens `tokenResponse.AccessToken` and others as provided by the implementation of the token generator used in `NewOAuthService` function

    ```

4.  **Token Introspection:**

    ```go
        introspection, err := oauthService.IntrospectToken(
            "token_to_inspect",
            "access_token",
            "client_id",
            "client_secret",
        )

    if introspection.Active {
            // Token is valid
            userID := introspection.Sub
            scope := introspection.Scope
    }
    ```

5.  **Session Management:**

    ```go
        // List user sessions
	    sessions, err := oauthService.GetUserSessions(userID)

        // Revoke a session
	    err = oauthService.RevokeSession(sessionID)

        // Cleanup expired sessions
	    err = oauthService.CleanupExpiredSessions(userID)

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
        // ... additional configuration
    }

	    oauth2API := ssso.NewOAuth2API(
		    oauthService,
		    jwksService,
		    clientService,
		    pkceService,
		    config,
    	)
```

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

We appreciate any form of contribution! Please take time to follow the rules on the official guidelines, you are always welcomed: **https://github.com/pilab-dev/shadow-sso/v1/blob/main/.github/CONTRIBUTING.md**.

## 📜 License

Shadow SSO is released under the MIT License, giving you full freedom on utilizing, sharing, changing, and distributing with all other parties (check license files for all the details).

## Contact 📞

If any doubt, send a direct email message to `gyula@pilab.hu` or join our public Discord channel by requesting invite on same email.

---

This updated README provides a clearer structure, utilizes visuals, and offers a more comprehensive explanation of Shadow SSO's features, usage, and security considerations. It's designed to be more engaging and helpful for potential users and contributors.
