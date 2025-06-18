# Using Service Account Keys

Service Account keys are JSON files that allow services (applications, scripts, etc.) to authenticate as the service account to access Shadow SSO-protected resources or other services that trust JWTs issued by Shadow SSO service accounts.

## Key Format

When you create a service account key using `ssoctl sa create-key`, you receive a JSON file similar in structure to Google Cloud Platform service account keys. It typically contains the following fields:

```json
{
  "type": "service_account",
  "project_id": "your-project-id",
  "private_key_id": "a_unique_key_id_string",
  "private_key": "-----BEGIN RSA PRIVATE KEY-----\n... (your RSA private key data) ...\n-----END RSA PRIVATE KEY-----\n",
  "client_email": "your-sa-name@your-project-id.iam.sso.dev",
  "client_id": "optional_client_id_associated_with_sa",
  "auth_uri": "https://your-sso-server.example.com/oauth2/auth",  // Example
  "token_uri": "https://your-sso-server.example.com/oauth2/token", // Example
  "auth_provider_x509_cert_url": "https://your-sso-server.example.com/oauth2/certs", // Example
  "client_x509_cert_url": "https://your-sso-server.example.com/oauth2/certs/your-sa-name@your-project-id.iam.sso.dev" // Example
}
```

-   **`type`**: Indicates the key type, usually "service_account".
-   **`project_id`**: The project associated with this service account.
-   **`private_key_id`**: A unique identifier for the private key. This ID is included in the `kid` header of JWTs signed by this key.
-   **`private_key`**: The PEM-encoded RSA private key used to sign JWTs. **This is sensitive and must be kept secure.**
-   **`client_email`**: The email address identifying the service account. This is typically used as the `iss` (issuer) and `sub` (subject) in the JWTs.
-   **`client_id`**: An optional OAuth client ID associated with the service account.
-   **`auth_uri`**, **`token_uri`**, **`auth_provider_x509_cert_url`**: These URIs point to your Shadow SSO's OAuth 2.0 endpoints. They are used by client libraries (like Google Cloud client libraries) to discover how to mint tokens or find public keys.
-   **`client_x509_cert_url`**: A URL that might point to public certificates associated with this service account's client ID (less commonly used directly for JWT signing compared to `auth_provider_x509_cert_url` for general IdP certs).

## Authentication Flow (Service-to-Service)

The primary use of a service account key is for a service to generate a short-lived JSON Web Token (JWT) that can be sent as a Bearer token to other services.

Here's the conceptual flow:

1.  **Load the Key**: Your application loads the downloaded JSON key file securely.
2.  **Construct JWT Claims**: Your application constructs a set of JWT claims. Minimally, this includes:
    *   `iss` (Issuer): Should be the `client_email` from the JSON key.
    *   `sub` (Subject): Usually the same as `iss`.
    *   `aud` (Audience): The identifier of the service or resource you want to access (e.g., "https://my-api.example.com" or a specific resource name). This is crucial for security.
    *   `exp` (Expiration Time): A short future timestamp (e.g., 1 hour from now).
    *   `iat` (Issued At): Current timestamp.
    *   (Optional) `scope`: Space-separated string of requested permissions.
    *   (Optional) `jti`: A unique JWT ID.
3.  **Sign the JWT**:
    *   Using a JWT library (e.g., `golang-jwt/jwt` in Go, `PyJWT` in Python, etc.), sign the constructed claims with the `private_key` from the JSON key.
    *   The signing algorithm should match what your `TokenService` expects (e.g., RS256).
    *   The `private_key_id` from the JSON key **must be included as the `kid` (Key ID) in the JWT header**. This allows the receiving service (via Shadow SSO's `TokenService`) to look up the correct public key for verification.
4.  **Send the JWT**:
    *   Your application sends the signed JWT as a Bearer token in the `Authorization` header to the target service:
        ```
        Authorization: Bearer <signed_jwt_string>
        ```
5.  **Token Validation (by Target Service / Shadow SSO)**:
    *   The target service (or an API gateway using Shadow SSO's `TokenService`) receives the JWT.
    *   It inspects the `kid` in the JWT header.
    *   It fetches the corresponding public key from Shadow SSO's `PublicKeyRepository` (via an internal mechanism or a JWKS URI if `auth_provider_x509_cert_url` is implemented as such).
    *   It verifies the JWT's signature using this public key.
    *   It validates the claims (`iss`, `aud`, `exp`, etc.).
    *   If valid, the request is authenticated as the service account.

## Using Google Cloud Client Libraries (Conceptual)

If you are familiar with Google Cloud, their client libraries often have built-in support for authenticating using service account JSON files (e.g., by setting the `GOOGLE_APPLICATION_CREDENTIALS` environment variable).

While Shadow SSO's keys are *formatted* like Google's, direct use with standard Google Cloud client libraries to access *Google Cloud services* won't work unless Shadow SSO itself is acting as a federated identity provider for GCP (which is an advanced setup).

However, you can often use the *same patterns or libraries* for JWT creation and signing:
-   Many Google Cloud authentication libraries (or underlying auth libraries) can parse these key files and provide utilities to sign JWTs.
-   Alternatively, use a standard JWT library for your programming language, load the private key from the JSON, and construct/sign the JWT manually as described above.

**Example (Conceptual Go using `golang-jwt/jwt`):**

```go
// This is a conceptual example. Error handling and library specifics may vary.
package main

import (
	"encoding/json"
	"io/ioutil"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type SAKeyFile struct {
	PrivateKeyID string `json:"private_key_id"`
	PrivateKey   string `json:"private_key"`
	ClientEmail  string `json:"client_email"`
	// ... other fields
}

func generateSAToken(keyFilePath, audience string) (string, error) {
	keyData, err := ioutil.ReadFile(keyFilePath)
	if err != nil {
		return "", err
	}

	var saKey SAKeyFile
	if err := json.Unmarshal(keyData, &saKey); err != nil {
		return "", err
	}

	rsaPrivKey, err := jwt.ParseRSAPrivateKeyFromPEM([]byte(saKey.PrivateKey))
	if err != nil {
		return "", err
	}

	claims := jwt.MapClaims{
		"iss": saKey.ClientEmail,
		"sub": saKey.ClientEmail,
		"aud": audience,
		"exp": time.Now().Add(time.Hour * 1).Unix(),
		"iat": time.Now().Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = saKey.PrivateKeyID

	return token.SignedString(rsaPrivKey)
}
```

**Security Best Practices:**
-   **Protect the Key File**: The JSON key file contains your private key. Treat it like any other sensitive credential. Do not embed it directly in source code. Use environment variables, secret management systems, or secure file permissions.
-   **Principle of Least Privilege**: Grant service accounts only the permissions they need.
-   **Regularly Rotate Keys**: Delete old keys and generate new ones periodically using `ssoctl sa delete-key` and `ssoctl sa create-key`.
