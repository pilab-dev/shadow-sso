# ssoctl CLI Tool Documentation

`ssoctl` is a command-line interface for managing users, service accounts, sessions, and other aspects of the Shadow SSO system.

## Installation

### From Source

```bash
# Clone the repository
git clone https://github.com/pilab-dev/shadow-sso.git
cd shadow-sso

# Build the CLI
make build
# This creates an executable named 'ssoctl' in the root directory

# Optional: Install to PATH
mv ssoctl /usr/local/bin/
```

### Using Go Install

```bash
go install github.com/pilab-dev/shadow-sso/apps/ssoctl@latest
```

### Docker Image

The `ssoctl` binary is now included in the official Shadow SSO Docker image (`ghcr.io/pilab-dev/shadow-sso-backend`):

```bash
# Run ssoctl from the Docker image
docker run --rm ghcr.io/pilab-dev/shadow-sso-backend:latest ssoctl --help

# Or use with a mounted config
docker run --rm -v ~/.ssoctl:/home/appuser/.ssoctl ghcr.io/pilab-dev/shadow-sso-backend:latest ssoctl user list
```

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

Comprehensive user lifecycle management including registration, profiles, security, and verification.

### Account Management

**1. Register a User:**
   Create new user accounts with initial setup.
   ```bash
   ssoctl user register --email newuser@example.com --first-name New --last-name User [--password <password>]
   # User registered successfully with pending activation status
   ```

**2. Activate a User:**
   Enable pending user accounts after verification.
   ```bash
   ssoctl user activate <user_id_or_email>
   # User activated and can now log in
   ```

**3. Lock/Unlock a User:**
   Temporarily disable or re-enable user access.
   ```bash
   ssoctl user lock <user_id_or_email>
   ssoctl user unlock <user_id_or_email>  # If unlock command exists
   ```

### User Information

**4. Get User Details:**
   Retrieve complete user profile information.
   ```bash
   ssoctl user get <user_id_or_email>
   # Displays: ID, email, names, status, roles, MFA status, last login, etc.
   ```

**5. List Users:**
   Administrative user listing with pagination.
   ```bash
   ssoctl user list [--page-size 10] [--page-token <token>] [--status active|pending|locked]
   # Paginated list with user metadata
   ```

**6. Update User Profile:**
   Modify user information (admin or self-service).
   ```bash
   ssoctl user update <user_id> --first-name "Updated Name" --email "newemail@example.com"
   ```

### Password Management

**7. Change Password:**
   Secure password updates with validation.
   ```bash
   # Self-service password change (requires current password):
   ssoctl user change-password --old-password <current> --new-password <new>

   # Admin password reset (no old password required):
   ssoctl user change-password <user_id> --new-password <new>
   ```

**8. Password Reset Flow:**
   Self-service password recovery.
   ```bash
   # Request password reset (sends email):
   ssoctl user request-password-reset --email user@example.com

   # Complete password reset (with token from email):
   ssoctl user reset-password --token <reset_token> --new-password <new_password>
   ```

### Phone Verification

**9. Phone Number Management:**
   Associate and verify phone numbers for enhanced security.
   ```bash
   # Set phone number:
   ssoctl user set-phone-number <user_id> --phone "+1234567890"

   # Send verification OTP:
   ssoctl user send-phone-verification <user_id>

   # Verify phone with OTP:
   ssoctl user verify-phone <user_id> --otp "123456"
   ```

### Email Verification

**10. Email Verification:**
    Manage email verification status.
    ```bash
    # Send verification email:
    ssoctl user send-email-verification <user_id>

    # Verify email with token:
    ssoctl user verify-email --token <verification_token>

    # Mark email as verified (admin):
    ssoctl user set-email-verified <user_id>
    ```

### Multi-Factor Authentication (`ssoctl mfa`)

Advanced MFA management supporting multiple authentication methods for enhanced security.

#### TOTP (Authenticator Apps)

**1. Setup TOTP:**
   Initialize TOTP with authenticator apps (Google Authenticator, Authy, etc.)
   ```bash
   ssoctl mfa totp setup
   # TOTP Setup Initiated:
   #   Secret: JBSWY3DPEHPK3PXP (for manual entry)
   #   QR Code URI: otpauth://totp/ShadowSSO:user@example.com?secret=JBSWY3DPEHPK3PXP&issuer=ShadowSSO
   #
   # Scan the QR code with your authenticator app, then verify:
   ```

**2. Verify TOTP Setup:**
   Complete TOTP setup and receive recovery codes.
   ```bash
   ssoctl mfa totp verify <totp_code>
   # 2FA (TOTP) enabled successfully!
   # Save these recovery codes securely:
   #   1. abc123-def456
   #   2. ghi789-jkl012
   ```

#### HOTP (Hardware Tokens)

**3. Setup HOTP:**
   Configure hardware-based one-time password tokens.
   ```bash
   ssoctl mfa hotp setup
   # HOTP Setup Initiated:
   #   Secret: JBSWY3DPEHPK3PXP
   #   QR Code URI: otpauth://hotp/ShadowSSO:user@example.com?secret=JBSWY3DPEHPK3PXP&issuer=ShadowSSO
   #   Initial Counter: 0
   ```

**4. Verify HOTP Setup:**
   ```bash
   ssoctl mfa hotp verify <hotp_code>
   # HOTP enabled successfully with recovery codes
   ```

#### Email-Based MFA

**5. Setup Email MFA:**
   Use email as a secondary authentication factor.
   ```bash
   ssoctl mfa email setup
   # Email MFA setup initiated. Check your inbox for verification code.
   ```

**6. Verify Email MFA:**
   ```bash
   ssoctl mfa email verify <email_otp>
   # Email MFA enabled successfully
   ```

#### Push Notification MFA (Firebase)

**7. Setup Push MFA:**
   Register mobile device for push notifications.
   ```bash
   # Register device token (obtained from mobile app):
   ssoctl mfa push register --token <firebase_device_token>

   # Enable push MFA:
   ssoctl mfa push enable
   # Push MFA enabled successfully
   ```

**8. Manage Push Devices:**
   ```bash
   # List registered devices:
   ssoctl mfa push devices

   # Remove device:
   ssoctl mfa push unregister --token <device_token>
   ```

#### MFA Challenge Management

**9. Send MFA Challenge:**
   Manually trigger MFA verification.
   ```bash
   ssoctl mfa challenge send
   # MFA challenge sent via your configured method
   ```

**10. Verify MFA Challenge:**
   Respond to MFA challenges.
   ```bash
   ssoctl mfa challenge verify <code>
   # MFA challenge verified successfully
   ```

**11. Check Push Challenge Status:**
   Monitor push notification challenges.
   ```bash
   ssoctl mfa push status --challenge-id <id>
   # Status: approved|denied|pending|expired
   ```

#### Recovery & Security

**12. Generate Recovery Codes:**
   Create new backup codes (invalidates old ones).
   ```bash
   ssoctl mfa recovery generate [--password-or-code <verification>]
   # New recovery codes:
   #   1. new123-code456
   #   2. backup789-secure012
   ```

**13. Disable MFA:**
   Remove all multi-factor authentication.
   ```bash
   ssoctl mfa disable [--password-or-code <verification>]
   # All MFA methods disabled. Account security reduced.
   ```

#### MFA Status & Information

**14. View MFA Status:**
   Check current MFA configuration.
   ```bash
   ssoctl mfa status
   # MFA Status: enabled
   # Methods:
   #   - TOTP: enabled
   #   - Push: enabled (2 devices)
   #   - Recovery Codes: available
   ```

**15. List Recovery Codes:**
   View remaining recovery codes without regenerating.
   ```bash
   ssoctl mfa recovery list
   # Remaining recovery codes: 8
   ```

## Phone Verification Commands (`ssoctl phone`)

SMS-based phone number verification for enhanced account security.

**1. Set Phone Number:**
   Associate a phone number with a user account.
   ```bash
   ssoctl phone set <user_id> --number "+1234567890"
   # Phone number set successfully
   ```

**2. Send Verification OTP:**
   Send SMS verification code to the user's phone.
   ```bash
   ssoctl phone send-otp <user_id>
   # Verification OTP sent to +1234567890
   ```

**3. Verify Phone Number:**
   Confirm phone ownership with the received OTP.
   ```bash
   ssoctl phone verify <user_id> --otp "123456"
   # Phone number verified successfully
   ```

## Password Reset Commands (`ssoctl password`)

Self-service password recovery and reset functionality.

**1. Request Password Reset:**
   Initiate password reset process (sends email with reset token).
   ```bash
   ssoctl password request-reset --email user@example.com
   # Password reset email sent to user@example.com
   ```

**2. Reset Password:**
   Complete password reset using token from email.
   ```bash
   ssoctl password reset --token <reset_token> --new-password <secure_password>
   # Password reset successfully
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

Advanced session management for security monitoring and control.

**1. List Sessions:**
   Display active user sessions with metadata.
   ```bash
   ssoctl session list [--user-id <target_user_id>] [--include-expired]
   # Active sessions with IP, User-Agent, creation time, expiry
   ```

**2. Clear Sessions:**
   Revoke specific or all user sessions for security.
   ```bash
   # Clear specific session:
   ssoctl session clear --session-id <session_id> [--user-id <target_user_id>]

   # Clear all sessions for a user (admin):
   ssoctl session clear --user-id <target_user_id>

   # Clear all sessions for current user (including current session):
   ssoctl session clear --all

   # Clear all other sessions (keep current session active):
   ssoctl session clear
   ```

## Identity Provider Management (`ssoctl idp`)

Manage external identity providers for federation.

**1. Add Identity Provider:**
   Configure external IdP (OIDC, SAML, LDAP).
   ```bash
   ssoctl idp add --name "Google OAuth" --type oidc \
     --client-id <client_id> --client-secret <secret> \
     --issuer-url https://accounts.google.com \
     --enabled=true
   ```

**2. List Identity Providers:**
   View configured external providers.
   ```bash
   ssoctl idp list [--only-enabled]
   # Configured IdPs with status and configuration
   ```

**3. Update Identity Provider:**
   Modify IdP configuration.
   ```bash
   ssoctl idp update <idp_id> --name "Updated Google" --enabled=false
   ```

**4. Delete Identity Provider:**
   Remove external provider configuration.
   ```bash
   ssoctl idp delete <idp_id>
   ```

## Federation Commands (`ssoctl federation`)

Manage cross-domain identity federation.

**1. List Federation Partners:**
   View configured federation relationships.
   ```bash
   ssoctl federation partners
   ```

**2. Configure Federation:**
   Set up federation with external domains.
   ```bash
   ssoctl federation configure --domain example.com --trust-level high
   ```

---
*This documentation provides an overview. For detailed command options, use `ssoctl <command> --help`.*
