# ssoctl CLI Tool Documentation

`ssoctl` is a command-line interface for managing users, service accounts, sessions, and other aspects of the Shadow SSO system.

## Installation

Currently, `ssoctl` can be built from source:
1.  Ensure you have Go installed on your system.
2.  Clone the repository: `git clone <repository_url>`
3.  Navigate to the repository root: `cd shadow-sso`
4.  Build the CLI: `make build`
    This will create an executable named `ssoctl` in the root directory.
5.  (Optional) Move the `ssoctl` executable to a directory in your system's PATH, e.g., `/usr/local/bin/`.

## Configuration

`ssoctl` uses a configuration file located at `$HOME/.ssoctl/config.yaml` by default. This file stores:
-   Server endpoint contexts (allowing you to switch between different SSO server instances).
-   Authentication tokens obtained via `ssoctl auth login`.

You can specify a different config file using the global `--config` flag:
`ssoctl --config /path/to/myconfig.yaml <command>`

### Context Management

Contexts allow you to define and switch between different Shadow SSO server endpoints easily. Each context stores a server endpoint and the authentication token associated with it.

**1. Set/Create a Context:**
   Use `set-context` to define a new context or modify an existing one. The `--server` flag is required.
   ```bash
   ssoctl config set-context my-dev-sso --server http://localhost:8080
   # Context "my-dev-sso" created/modified.
   # If this is the first context or no context is current, it will be set as the current context.
   ```

**2. List Contexts:**
   View all defined contexts and the currently active one.
   ```bash
   ssoctl config get-contexts
   # Output (YAML format):
   # contexts:
   #   my-dev-sso:
   #     name: my-dev-sso
   #     server_endpoint: http://localhost:8080
   #     user_auth_token: <your_auth_token_if_logged_in>
   #   my-prod-sso:
   #     name: my-prod-sso
   #     server_endpoint: https://sso.example.com
   # Current context: my-dev-sso
   ```

**3. Switch Context:**
   Set the active context.
   ```bash
   ssoctl config use-context my-prod-sso
   # Switched to context "my-prod-sso".
   ```

**4. View Current Context:**
   Display the name of the currently active context.
   ```bash
   ssoctl config current-context
   # my-prod-sso
   ```

## Authentication Commands (`ssoctl auth`)

Commands for logging in and out of the SSO server.

**1. Login:**
   Authenticates with the SSO server using your email and password. The obtained session token is stored in the current context.
   If 2FA is enabled for your account, you will be prompted to complete the second factor authentication via a separate command after successful password verification.
   ```bash
   ssoctl auth login
   # Enter email: user@example.com
   # Enter password:
   # Login successful (or 2FA required). Token saved for context 'my-dev-sso'.
   # Logged in as: user@example.com (ID: <user_id>)
   # OR if 2FA is required:
   # 2FA is required for this account.
   # Please run 'ssoctl auth verify-2fa --token <2fa_session_token> --code <your_totp_code>'
   ```
   If already logged in for the current context, it will ask for confirmation to re-login.

**2. Verify 2FA (TOTP/Recovery Code):**
   (This command might be part of `auth` or a top-level command, TBD by user based on actual proto definition. Assuming `ssoctl auth verify-2fa` for now).
   After the initial login indicates 2FA is required, use this command to submit your TOTP or a recovery code.
   ```bash
   ssoctl auth verify-2fa --token <2fa_session_token_from_login_step> --code <your_totp_or_recovery_code>
   # Login successful. Token saved for context 'my-dev-sso'.
   # Logged in as: user@example.com (ID: <user_id>)
   ```
   *(Note: The exact flags/args for `verify-2fa` depend on how `AuthService.Verify2FA` RPC is called by the CLI. The CLI implementation for this step is not part of the current subtask.)*

**3. Logout:**
   Logs out from the SSO server by invalidating the current session token on the server and clearing it from the local configuration for the current context.
   ```bash
   ssoctl auth logout
   # Logged out successfully from context 'my-dev-sso'. Local token cleared.
   ```

## User Management Commands (`ssoctl user`)

Commands for managing user accounts.

**1. Register a User:**
   Typically requires administrator privileges.
   ```bash
   ssoctl user register --email newuser@example.com --first-name New --last-name User [--password <password>]
   # (Prompts for password if not provided)
   # User registered successfully:
   # (YAML output of the new user)
   ```

**2. Get User Details:**
   ```bash
   ssoctl user get <user_id_or_email>
   # (YAML output of the user details)
   ```

**3. List Users:**
   Lists users with pagination. Typically requires admin privileges.
   ```bash
   ssoctl user list [--page-size 10] [--page-token <token>]
   # (YAML output of user list)
   # Next page token: <next_token_if_any>
   ```

**4. Activate a User:**
   Typically requires admin privileges.
   ```bash
   ssoctl user activate <user_id_or_email>
   # User <user_id_or_email> activated successfully.
   ```

**5. Lock a User:**
   Typically requires admin privileges.
   ```bash
   ssoctl user lock <user_id_or_email>
   # User <user_id_or_email> locked successfully.
   ```

**6. Change Password:**
   Allows an administrator to change a user's password, or a user to change their own password.
   ```bash
   # Admin changing password for a user:
   ssoctl user change-password <user_id_or_email> [--new-password <password>]
   # (Prompts for new password if not provided)

   # User changing their own password (assuming logged in as that user):
   ssoctl user change-password <their_own_user_id_or_email> --old-password <current_password> [--new-password <password>]
   # (Prompts for new password if not provided)
   ```

### User 2FA Management (`ssoctl user 2fa ...`)
   These are self-service commands for managing your own Two-Factor Authentication settings.

**1. Setup TOTP:**
   Initiates the Time-based One-Time Password (TOTP) setup for your account.
   ```bash
   ssoctl user 2fa setup
   # TOTP Setup Initiated:
   #   Secret (for manual entry): <BASE32_SECRET_KEY>
   #   QR Code URI: otpauth://totp/YourAppName:user@example.com?secret=<BASE32_SECRET_KEY>&issuer=YourAppName
   #
   # Scan the QR code with your authenticator app (e.g., Google Authenticator, Authy).
   # ...
   # After scanning/entering, use 'ssoctl user 2fa verify <TOTP_CODE>' to enable 2FA.
   ```

**2. Verify and Enable TOTP:**
   Verifies the TOTP code from your authenticator app and enables 2FA.
   ```bash
   ssoctl user 2fa verify <totp_code_from_app>
   # 2FA (TOTP) enabled successfully!
   # Store these recovery codes securely...:
   #   1. <recovery_code_1>
   #   ...
   ```

**3. Disable 2FA:**
   Disables 2FA for your account. Requires re-authentication (password or a current 2FA code).
   ```bash
   ssoctl user 2fa disable [--password-or-code <current_password_or_2fa_code>]
   # (Prompts for password or 2FA code if not provided)
   # 2FA disabled successfully for your account.
   ```

**4. Generate New Recovery Codes:**
   Generates a new set of recovery codes, invalidating any old ones. Requires 2FA to be enabled. May require re-authentication.
   ```bash
   ssoctl user 2fa recovery-codes [--password-or-code <current_password_or_2fa_code>]
   # (Prompts for password or 2FA code if not provided and server requires it)
   # New recovery codes generated. Store these securely...:
   #   1. <new_recovery_code_1>
   #   ...
   ```

## OAuth Client Management Commands (`ssoctl client`)

Commands for managing OAuth2 client applications. These typically require administrator privileges.

**1. Register a Client:**
   ```bash
   ssoctl client register --name "My App" --type confidential --redirect-uris "http://localhost:8080/callback,https://myapp.com/callback" --scopes "openid,profile,email" --grant-types "authorization_code,refresh_token"
   # Client registered successfully:
   # client_id: <generated_client_id>
   # client_name: My App
   # client_secret: <generated_client_secret_for_confidential_clients>
   # ... (other details in YAML)
   # IMPORTANT: Store the client_secret securely. It will not be shown again.
   ```

**2. Get Client Details:**
   ```bash
   ssoctl client get <client_id>
   # (YAML output of the client details, client_secret is not shown)
   ```

**3. List Clients:**
   Lists registered OAuth2 clients with pagination.
   ```bash
   ssoctl client list [--page-size 10] [--page-token <token>]
   # (YAML output of client list)
   # Next page token: <next_token_if_any>
   ```

**4. Update a Client:**
   ```bash
   ssoctl client update <client_id> --name "My Updated App" --redirect-uris "https://new.myapp.com/callback" --active=false
   # Client updated successfully:
   # (YAML output of updated client details)
   ```

**5. Delete a Client:**
   ```bash
   ssoctl client delete <client_id> [--force]
   # (Prompts for confirmation if --force is not used)
   # Client '<client_id>' deleted successfully.
   ```

## Identity Provider (IdP) Management Commands (`ssoctl idp`)

Commands for managing external Identity Provider configurations (e.g., OIDC providers). These typically require administrator privileges.

**1. Add an IdP Configuration:**
   ```bash
   ssoctl idp add --name "Login with Google" --type OIDC --enabled=true \
     --oidc-client-id "google-client-id" --oidc-client-secret "google-client-secret" \
     --oidc-issuer-url "https://accounts.google.com" \
     --oidc-scopes "openid,profile,email" \
     --map-attribute "email=Email" --map-attribute "name=FirstName"
   # IdP configuration added successfully:
   # (YAML output of the new IdP configuration, client secret is not shown)
   ```

**2. Get IdP Configuration Details:**
   ```bash
   ssoctl idp get <idp_id>
   # (YAML output of the IdP configuration details, client secret is not shown)
   ```

**3. List IdP Configurations:**
   ```bash
   ssoctl idp list [--only-enabled]
   # (YAML output of IdP configuration list)
   ```

**4. Update an IdP Configuration:**
   ```bash
   ssoctl idp update <idp_id> --name "Google Login (Updated)" --enabled=false --oidc-scopes "openid,email"
   # IdP configuration updated successfully:
   # (YAML output of updated IdP configuration, client secret is not shown)
   ```

**5. Delete an IdP Configuration:**
   ```bash
   ssoctl idp delete <idp_id>
   # IdP configuration '<idp_id>' deleted successfully.
   ```

## Service Account Commands (`ssoctl service-account` or `ssoctl sa`)

Commands for managing service accounts and their keys. These typically require administrator privileges.

**1. Create Service Account Key:**
   Creates a service account (if it doesn't exist based on project ID/email) and generates a new JSON key for it.
   ```bash
   ssoctl sa create-key --project-id <project_id> [--client-email <email>] [--display-name <name>]
   # (Outputs the service account key in JSON format to stdout)
   # Service Account ID: <service_account_id> (to stderr)
   ```
   Save the JSON output to a file to use it for service authentication.

**2. List Service Account Keys:**
   Lists metadata of active public keys for a given service account.
   ```bash
   ssoctl sa list-keys <service_account_id>
   # (YAML output of key metadata list)
   ```

**3. Delete Service Account Key:**
   Revokes/deletes a specific service account key.
   ```bash
   ssoctl sa delete-key <service_account_id> <key_id>
   # Service account key '<key_id>' for service account '<service_account_id>' deleted successfully.
   ```

## Session Management Commands (`ssoctl session`)

Commands for managing user login sessions.

**1. List Sessions:**
   Lists active sessions. Defaults to the current authenticated user. Admins can use `--user-id` to specify another user.
   ```bash
   ssoctl session list [--user-id <target_user_id>]
   # Active sessions:
   # (YAML output of session list)
   ```

**2. Clear Sessions:**
   Clears/revokes sessions.
   ```bash
   # Clear a specific session by its ID (for current user or specified --user-id)
   ssoctl session clear --session-id <session_id_to_clear> [--user-id <target_user_id>]

   # Clear all sessions for a specific user (admin)
   ssoctl session clear --user-id <target_user_id>
   # (The --all flag can be used for clarity but is implicit if --session-id is not given for a specific user)

   # Clear all sessions for the current authenticated user (including the ssoctl session itself)
   ssoctl session clear --all

   # Clear all *other* sessions for the current authenticated user (leaving ssoctl session active)
   # This is the default behavior of 'ssoctl session clear' when no flags are provided for the current user.
   ssoctl session clear
   ```

---
*This documentation provides an overview. For detailed command options, use `ssoctl <command> --help`.*
