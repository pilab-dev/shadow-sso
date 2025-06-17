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
   ```bash
   ssoctl auth login
   # Enter email: user@example.com
   # Enter password:
   # Login successful. Token saved for context 'my-dev-sso'.
   # Logged in as: user@example.com (ID: <user_id>)
   ```
   If already logged in for the current context, it will ask for confirmation to re-login.

**2. Logout:**
   Logs out from the SSO server by invalidating the current session token on the server and clearing it from the local configuration for the current context.
   ```bash
   ssoctl auth logout
   # Logged out successfully from context 'my-dev-sso'. Local token cleared.
   ```

## User Management Commands (`ssoctl user`)

Commands for managing user accounts. These typically require administrator privileges (i.e., logged in as an admin user).

**1. Register a User:**
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
   Lists users with pagination.
   ```bash
   ssoctl user list [--page-size 10] [--page-token <token>]
   # (YAML output of user list)
   # Next page token: <next_token_if_any>
   ```

**4. Activate a User:**
   ```bash
   ssoctl user activate <user_id_or_email>
   # User <user_id_or_email> activated successfully.
   ```

**5. Lock a User:**
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
