#!/bin/bash
# Seed KeePassXC vault with secrets from shadow-sso workspace
# Usage: ./scripts/seed-vault.sh
# The vault password is read from stdin (hidden) — never stored or echoed.

set -euo pipefail

VAULT="${HOME}/Workspace/Passwords.kdbx"

if [ ! -f "$VAULT" ]; then
  echo "❌ Vault not found at $VAULT"
  exit 1
fi

# Read vault password silently
echo "Enter KeePassXC vault password:"
read -s VAULT_PW
echo

# Verify password
echo "$VAULT_PW" | keepassxc-cli ls "$VAULT" > /dev/null 2>&1 || {
  echo "❌ Invalid vault password"
  exit 1
}
echo "✅ Vault unlocked"

add_entry() {
  local title="$1"
  local username="$2"
  local password="$3"
  echo "  → $title"
  printf "%s\n%s\n%s\n" "$VAULT_PW" "$username" "$password" | \
    keepassxc-cli add -p -u "$VAULT" "$title" > /dev/null 2>&1 || true
}

echo ""
echo "Adding entries to KeePassXC vault..."

# ============================================================
# CATEGORY 1: Live/infra credentials
# ============================================================

add_entry "shadow-sso/MongoDB Atlas" "pirat" "b0tZrF1rZHoJfd0X"
add_entry "shadow-sso/MongoDB URI" "uri" "mongodb+srv://pirat:b0tZrF1rZHoJfd0X@sandbox.yuwak.mongodb.net/sso_dev?retryWrites=true&w=majority&minPoolSize=15&appName=Sandbox&authSource=admin"
add_entry "shadow-sso/JWT HS256 Fallback Key" "jwt-fallback" "temporary-secret-for-hs256-change-me"

# ============================================================
# CATEGORY 2: Helm chart default credentials (should be changed)
# ============================================================

add_entry "shadow-sso/Helm Admin Password" "admin" "changemeStrongPassword123!"
add_entry "shadow-sso/Helm MongoDB Root Password" "mongodb-root" "changeme"
add_entry "shadow-sso/Helm MongoDB User Password" "mongodb-user" "changeme_ssso"

# ============================================================
# CATEGORY 3: Notification service credentials (.env.example)
# ============================================================

add_entry "shadow-sso/Resend API Key" "resend" "your_resend_api_key"
add_entry "shadow-sso/Twilio Account SID" "twilio-sid" "your-twilio-sid"
add_entry "shadow-sso/Twilio Auth Token" "twilio-token" "your-twilio-auth-token"
add_entry "shadow-sso/Twilio Phone Number" "twilio-phone" "+1234567890"

# ============================================================
# CATEGORY 4: CI/CD tokens
# ============================================================

add_entry "shadow-sso/Codecov Token" "codecov" "KWTJG0ADS0"

echo ""
echo "✅ Done! All secrets added to KeePassXC vault."
echo ""
echo "📌 Post-install steps:"
echo "  1. Open KeePassXC app to review entries"
echo "  2. Rotate the MongoDB Atlas password (Task 0)"
echo "  3. Update .env to remove inline credentials (reference vault instead)"
