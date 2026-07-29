---
id: mfa
title: Multi-Factor Authentication
sidebar_label: MFA
---

# Multi-Factor Authentication

Configure and use multi-factor authentication (MFA) to add an extra layer of security to user accounts.

## Overview

Shadow SSO supports multiple MFA methods:

| Method | Description | Security Level |
|--------|-------------|----------------|
| **TOTP** | Time-based one-time password (authenticator apps) | High |
| **Email** | One-time code sent via email | Medium |
| **Push** | Push notification to mobile device | High |
| **SMS** | One-time code sent via SMS | Low |
| **Recovery Codes** | Backup codes for account recovery | High |

## TOTP (Authenticator Apps)

### Setup TOTP

Users can enable TOTP via the CLI:

```bash
# Start TOTP setup
ssoctl user 2fa setup

# Output:
# Scan this QR code with your authenticator app:
# [QR Code]
# Or enter this secret manually: JBSWY3DPEHPK3PXP
# 
# Enter the 6-digit code from your app to verify:
```

### Verify TOTP

```bash
# Verify with code from authenticator app
ssoctl user 2fa verify 123456
```

### Disable TOTP

```bash
# Disable TOTP (requires current TOTP code or recovery code)
ssoctl user 2fa disable -p 123456
```

### Supported Apps

| App | Platform |
|-----|----------|
| Google Authenticator | iOS, Android |
| Authy | iOS, Android, Desktop |
| Microsoft Authenticator | iOS, Android |
| 1Password | iOS, Android, Desktop |
| Bitwarden | iOS, Android, Desktop |

## Email MFA

### Enable Email MFA

```bash
# Configure email MFA
ssoctl user 2fa email enable

# Verify email is configured
ssoctl user 2fa status
```

### Email Configuration

Ensure email service is configured:

```bash
SSSO_RESEND_API_KEY=re_your_api_key
SSSO_FROM_EMAIL=noreply@example.com
SSSO_NEXT_PUBLIC_BASE_URL=https://app.example.com
```

## Push MFA (Firebase)

### Setup Push MFA

1. Configure Firebase in Shadow SSO:

```bash
SSSO_FIREBASE_PROJECT_ID=your-project-id
SSSO_FIREBASE_CREDENTIALS_PATH=/etc/sso/firebase/credentials.json
```

2. User registers device:

```bash
# Register device for push notifications
ssoctl user 2fa push register --device-token <firebase-token>
```

### Push Flow

```
1. User enters password
2. Shadow SSO sends push notification to registered device
3. User approves/denies on mobile device
4. Shadow SSO completes authentication
```

## SMS MFA (Twilio)

### Configure SMS

```bash
SSSO_TWILIO_ACCOUNT_SID=ACxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
SSSO_TWILIO_AUTH_TOKEN=your_auth_token
SSSO_TWILIO_PHONE_NUMBER=+1234567890
```

### Enable SMS MFA

```bash
# Add phone number
ssoctl user phone verify --phone "+1234567890"

# Enable SMS MFA
ssoctl user 2fa sms enable
```

## Recovery Codes

### Generate Recovery Codes

```bash
# Generate new recovery codes
ssoctl user 2fa recovery-codes

# Output:
# Your recovery codes:
# 1. abc123-def456
# 2. ghi789-jkl012
# 3. mno345-pqr678
# ...
# 
# Store these codes securely. Each code can only be used once.
```

### Use Recovery Code

```bash
# Login with recovery code when MFA device unavailable
ssoctl auth login
# Enter password
# Enter MFA code: <recovery-code>
```

## Authentication Flow

### Login with MFA

```
1. User enters email and password
2. Shadow SSO validates credentials
3. If MFA enabled:
   a. Shadow SSO returns two_factor_required: true
   b. User receives MFA challenge (TOTP prompt, email code, push notification)
   c. User provides MFA code/response
   d. Shadow SSO validates MFA
   e. Issue tokens
4. If MFA not enabled:
   a. Issue tokens directly
```

### API Example

```bash
# Step 1: Login with password
curl -X POST https://sso.example.com/oauth2/token \
  -d "grant_type=password" \
  -d "username=user@example.com" \
  -d "password=secret"

# Response (MFA required):
{
  "two_factor_required": true,
  "two_factor_session_token": "2fa-session-xyz",
  "mfa_methods": ["totp", "email", "recovery"]
}

# Step 2: Verify MFA
curl -X POST https://sso.example.com/oauth2/2fa/verify \
  -d "two_factor_session_token=2fa-session-xyz" \
  -d "totp_code=123456"

# Response (success):
{
  "access_token": "...",
  "refresh_token": "...",
  "token_type": "Bearer"
}
```

## GraphQL API

### Query MFA Status

```graphql
query {
  user(id: "user-123") {
    email
    twoFactorEnabled
    twoFactorMethods
    recoveryCodesRemaining
  }
}
```

### Enable TOTP

```graphql
mutation {
  setupTOTP(userId: "user-123") {
    secret
    qrCodeUrl
  }
}
```

### Verify TOTP

```graphql
mutation {
  verifyTOTP(userId: "user-123", code: "123456") {
    success
    recoveryCodes
  }
}
```

## Admin Management

### View User MFA Status

```bash
# Check MFA status
ssoctl user 2fa status <user-id>

# Output:
# MFA Status for user@example.com:
# Enabled: true
# Methods: TOTP, Email
# Recovery codes remaining: 8/10
```

### Reset User MFA

```bash
# Admin can disable MFA for a user
ssoctl user 2fa disable --user <user-id> --admin-override
```

### Force MFA Enrollment

```bash
# Require MFA for all users
ssoctl realm settings update --require-mfa true
```

## Security Considerations

### MFA Method Comparison

| Method | Phishing Resistant | Convenience | Setup Complexity |
|--------|-------------------|-------------|------------------|
| TOTP | No | High | Low |
| Push | No | High | Medium |
| Email | No | Medium | Low |
| SMS | No | High | Low |
| WebAuthn/FIDO2 | Yes | High | Medium |

### Recommendations

1. **Prefer TOTP or Push** over SMS (SMS is vulnerable to SIM swapping)
2. **Generate recovery codes** and store securely
3. **Require MFA** for admin accounts
4. **Monitor** failed MFA attempts
5. **Educate users** about MFA importance

### Rate Limiting

MFA attempts are rate-limited:

```bash
# Default: 5 attempts per 15 minutes
SSSO_RATE_LIMIT_MAX_ATTEMPTS=5
SSSO_RATE_LIMIT_LOCKOUT_DURATION=15m
```

## Troubleshooting

### TOTP Code Rejected

**Issue:** Valid TOTP code rejected.

**Solutions:**
1. Check device time is synchronized
2. Verify correct authenticator app is used
3. Check time window tolerance (±30 seconds)

### Email Code Not Received

**Issue:** MFA email not arriving.

**Diagnosis:**

```bash
# Check email service logs
kubectl logs deployment/ssso-backend | grep resend

# Verify email configuration
echo $SSSO_RESEND_API_KEY
echo $SSSO_FROM_EMAIL
```

### Push Notification Not Received

**Issue:** Push notification not arriving.

**Diagnosis:**

```bash
# Check Firebase configuration
echo $SSSO_FIREBASE_PROJECT_ID
ls -la $SSSO_FIREBASE_CREDENTIALS_PATH

# Check device registration
ssoctl user 2fa push devices <user-id>
```

### Lost MFA Device

**Solution:** Use recovery code:

```bash
ssoctl auth login
# Enter password
# When prompted for MFA, enter recovery code instead
```

If no recovery codes available, admin can reset:

```bash
ssoctl user 2fa disable --user <user-id> --admin-override
```

## Next Steps

- [Federation](/features/federation) - External identity providers
- [Service Accounts](/features/service-accounts) - Machine identities
- [Security](/operations/security) - Security best practices
