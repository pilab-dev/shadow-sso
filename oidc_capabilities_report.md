# OIDC Capabilities Report for Shadow SSO Server

## 1. Introduction

This report outlines the OpenID Connect (OIDC) capabilities of the Shadow SSO server. The server's features are configured through the `OpenIDProviderConfig` structure, and these capabilities are exposed via the OIDC discovery endpoint (`/.well-known/openid-configuration`). This document reflects the server's potential capabilities based on its configuration structure.

## 2. Key OIDC Endpoints

The availability of OIDC endpoints is configurable via the `EnabledEndpoints` section in `OpenIDProviderConfig`.

*   **Issuer:** The issuer URI is configurable via `OpenIDProviderConfig.Issuer`. If not set, it defaults to the base URL of the server.
*   **Authorization Endpoint (`/oauth2/authorize`):** Availability is controlled by `EnabledEndpoints.Authorization`.
*   **Token Endpoint (`/oauth2/token`):** Availability is controlled by `EnabledEndpoints.Token`.
*   **UserInfo Endpoint (`/oauth2/userinfo`):** Availability is controlled by `EnabledEndpoints.UserInfo`.
*   **JWKS URI (`/.well-known/jwks.json`):** Availability is controlled by `EnabledEndpoints.JWKS`.
*   **Introspection Endpoint (`/oauth2/introspect`):** Availability is controlled by `EnabledEndpoints.Introspection`. The path is `/oauth2/introspect`.
*   **Revocation Endpoint (`/oauth2/revoke`):** Availability is controlled by `EnabledEndpoints.Revocation`. The path is `/oauth2/revoke`.
*   **End Session Endpoint (`/oauth2/logout`):** Availability is controlled by `EnabledEndpoints.EndSession`. The path is assumed to be `/oauth2/logout`.
*   **Registration Endpoint (`/oauth2/register`):** Availability is controlled by `EnabledEndpoints.Registration`. The path is assumed to be `/oauth2/register`.

## 3. Supported Grant Types

The server supports various grant types, configurable via `EnabledGrantTypes` in `OpenIDProviderConfig`. The OIDC discovery document will list the following if enabled:

*   `authorization_code` (controlled by `EnabledGrantTypes.AuthorizationCode`)
*   `client_credentials` (controlled by `EnabledGrantTypes.ClientCredentials`)
*   `refresh_token` (controlled by `EnabledGrantTypes.RefreshToken`)
*   `password` (controlled by `EnabledGrantTypes.Password`) - *Note: Resource Owner Password Credentials grant is generally discouraged in modern OAuth 2.0.*
*   `implicit` (controlled by `EnabledGrantTypes.Implicit`) - *Note: "implicit" itself is not a grant type for the token endpoint but indicates support for flows issuing tokens directly from the authorization endpoint.*
*   `urn:ietf:params:oauth:grant-type:jwt-bearer` (controlled by `EnabledGrantTypes.JWTBearer`)
*   `urn:ietf:params:oauth:grant-type:device_code` (controlled by `EnabledGrantTypes.DeviceCode`)

## 4. Supported Response Types

The list of supported response types is directly configurable via `OpenIDProviderConfig.TokenConfig.SupportedResponseTypes`. These determine the combinations of code, token, and ID token that can be requested.

## 5. Supported Response Modes

The list of supported response modes is directly configurable via `OpenIDProviderConfig.TokenConfig.SupportedResponseModes`. If not configured, it defaults to `["query", "fragment", "form_post"]`.

## 6. Scopes and Claims

*   **Supported Scopes:** The scopes offered by the server are configurable via `OpenIDProviderConfig.ClaimsConfig.SupportedScopes`.
*   **Supported Claims:** The claims that can be returned in tokens or via the UserInfo endpoint are configurable via `OpenIDProviderConfig.ClaimsConfig.SupportedClaims`. The server also supports claim mappings via `OpenIDProviderConfig.ClaimsConfig.ClaimsMappings`.
*   **Claims Parameter Support:** The server's support for the `claims` request parameter is controlled by `OpenIDProviderConfig.ClaimsConfig.EnableClaimsParameter`.

## 7. Client Authentication

Methods supported for authenticating clients at the token endpoint are configurable via `OpenIDProviderConfig.TokenConfig.SupportedTokenEndpointAuth`.

## 8. Token Signing & Encryption

*   **ID Token Signing Algorithms:** Configurable via `OpenIDProviderConfig.SecurityConfig.AllowedSigningAlgs`.
*   **UserInfo Signing Algorithms:** Configurable via `OpenIDProviderConfig.SecurityConfig.AllowedSigningAlgs` (assuming UserInfo responses can be signed JWTs and use the same set of algorithms).
*   **Request Object Signing Algorithms:** Configurable via `OpenIDProviderConfig.SecurityConfig.AllowedSigningAlgs`.
*   **Encryption Algorithms:** The server configuration (`OpenIDProviderConfig.SecurityConfig`) also includes fields for `AllowedEncryptionAlgs` and `AllowedEncryptionEnc`, suggesting support for encrypted tokens or request objects, though their specific application to ID Tokens, UserInfo, etc., would be detailed by corresponding fields in the discovery document if populated (e.g., `id_token_encryption_alg_values_supported`).

## 9. PKCE (Proof Key for Code Exchange)

*   **PKCE Support:** PKCE can be enabled or disabled via `OpenIDProviderConfig.PKCEConfig.Enabled`.
*   **Supported Methods:** If PKCE is enabled, the supported challenge methods (e.g., "S256") are listed in `OpenIDProviderConfig.PKCEConfig.SupportedMethods`. The server can also be configured to allow the "plain" method via `OpenIDProviderConfig.PKCEConfig.AllowPlainChallengeMethod`.
*   The server can be configured to require PKCE for all requests (`SecurityConfig.RequirePKCE`) or specifically for public clients (`SecurityConfig.RequirePKCEForPublicClients`).

## 10. Other Features

*   **Request Parameter Support:** The OIDC discovery document indicates support for the `request` parameter (hardcoded to `true` in the handler, implying it's generally supported).
*   **Request URI Parameter Support:** The OIDC discovery document indicates support for the `request_uri` parameter (hardcoded to `true` in the handler, implying it's generally supported).
*   **Require Request URI Registration:** The server can be configured to require that `request_uri` values are pre-registered, via `OpenIDProviderConfig.SecurityConfig.RequireRequestURIRegistration`.
*   **Access Token Format:** The format of access tokens (e.g., "jwt" or "opaque") is configurable via `OpenIDProviderConfig.TokenConfig.AccessTokenFormat`.
*   **Token Lifetimes:** TTLs for access tokens, refresh tokens, authorization codes, and ID tokens are all configurable.
*   **Consent Behavior:** The server has settings for requiring and forcing user consent (`RequireConsent`, `ForceConsent`).
*   **Session Management:** A session TTL is configurable (`SessionTTL`).
*   **Key Rotation:** A key rotation period is configurable (`KeyRotationPeriod`).
*   **Security Flags:** Various security flags like `RequireSignedRequestObject`, `DefaultMaxAge`, `RequireAuthTime` are available in `SecurityConfig`.

This report provides a high-level overview of the Shadow SSO server's OIDC capabilities based on its configuration structure. The exact features and their values in a live deployment will depend on the specific instance's `OpenIDProviderConfig`.
