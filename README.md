# SSO Package

A comprehensive OAuth 2.0 and OpenID Connect implementation in Go, providing secure authentication and authorization services.

## Features

- Full OAuth 2.0 implementation (RFC 6749)
- OpenID Connect support
- PKCE support (RFC 7636)
- Token Introspection (RFC 7662)
- Token Revocation (RFC 7009)
- Session Management
- Multiple grant types support:
  - Authorization Code
  - Client Credentials
  - Resource Owner Password
  - Refresh Token
- Secure token handling
- Client application management
- User session management

## Installation

```bash
go get github.com/pilab-dev/shadow-sso
```

## Quick Start

### 1. Initialize the Services

```go
package main

import (
    "github.com/labstack/echo/v4"
    ssso "github.com/pilab-dev/shadow-sso"
)

func main() {
    // Initialize repositories
    oauthRepo := NewYourOAuthRepository()  // Implement OAuthRepository interface
    userRepo := NewYourUserRepository()    // Implement UserRepository interface
    
    // Generate or load RSA signing key
    signingKey := loadSigningKey()
    
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
    e.Start(":8080")
}
```

### 2. Register a Client Application

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
```

### 3. Authorization Code Flow Example

```go
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
```

### 4. Token Introspection

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

### 5. Session Management

```go
// List user sessions
sessions, err := oauthService.GetUserSessions(userID)

// Revoke a session
err = oauthService.RevokeSession(sessionID)

// Cleanup expired sessions
err = oauthService.CleanupExpiredSessions(userID)
```

## Security Features

- Constant-time comparisons for sensitive data
- PKCE support for public clients
- Secure token storage
- Session management and revocation
- Token introspection
- Scope validation
- Client authentication

## Configuration

The package can be configured through the `OpenIDProviderConfig`:

```go
config := &sso.OpenIDProviderConfig{
    Issuer:                "https://your-issuer.com",
    AuthorizationEndpoint: "https://your-issuer.com/oauth2/authorize",
    TokenEndpoint:         "https://your-issuer.com/oauth2/token",
    UserInfoEndpoint:      "https://your-issuer.com/oauth2/userinfo",
    JwksURI:              "https://your-issuer.com/.well-known/jwks.json",
    // ... additional configuration
}
```

## Implementing Required Interfaces

The package requires implementation of several interfaces:

- `OAuthRepository`: Handles OAuth-related data storage
- `UserRepository`: Manages user data and sessions
- `TokenStore`: Optional interface for token caching

Example implementation stubs are provided in the documentation.

## Error Handling

The package provides standardized OAuth 2.0 errors through the `errors` package:

```go
if err := validateRequest(); err != nil {
    return errors.NewInvalidRequest("Invalid request parameters")
}
```

## Contributing

Contributions are welcome! Please read our contributing guidelines and submit pull requests.

## License

This project is licensed under the MIT License - see the LICENSE file for details.
