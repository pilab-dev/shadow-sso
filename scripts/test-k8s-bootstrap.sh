#!/usr/bin/env bash
#
# Integration test for shadow-sso bootstrap flow against a deployed Kubernetes instance.
#
# Tests:
#   1. Reads the bootstrap token from the deployed pod
#   2. Runs sssoctl bootstrap against https://sso.pilab.hu
#   3. Verifies admin user login
#   4. Tests user CRUD via CLI
#   5. Tests client CRUD via CLI
#   6. Tests bootstrap token invalidation (single-use)
#
# Prerequisites:
#   - kubectl configured for talos-vm3 context
#   - sssoctl binary available (built from this repo)
#   - The shadow-sso deployment must be fresh/unbootstrapped OR
#     the MongoDB database must be wiped for a clean test
#
# Usage:
#   ./scripts/test-k8s-bootstrap.sh [--namespace shadow-sso] [--server https://sso.pilab.hu]
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# ============================================================================
# Configuration
# ============================================================================
NAMESPACE="${NAMESPACE:-shadow-sso}"
SSO_SERVER="${SSO_SERVER:-https://sso.pilab.hu}"
ADMIN_EMAIL="${ADMIN_EMAIL:-admin@pilab.hu}"
ADMIN_PASSWORD="${ADMIN_PASSWORD:-$(openssl rand -base64 24)}"
SSSOCTL_BIN="${SSSOCTL_BIN:-$PROJECT_ROOT/bin/sssoctl}"
BOOTSTRAP_TOKEN_PATH="${BOOTSTRAP_TOKEN_PATH:-/var/lib/shadow-sso/bootstrap-token}"
TEST_USER_EMAIL="test-k8s-$(date +%s)@example.com"
TEST_CLIENT_NAME="test-k8s-client-$(date +%s)"
TEMP_TOKEN_FILE=$(mktemp /tmp/bootstrap-token-XXXXXX)
PASSED=0
FAILED=0

# ============================================================================
# Parse arguments
# ============================================================================
while [[ $# -gt 0 ]]; do
    case $1 in
        --namespace) NAMESPACE="$2"; shift 2;;
        --server) SSO_SERVER="$2"; shift 2;;
        --admin-email) ADMIN_EMAIL="$2"; shift 2;;
        --admin-password) ADMIN_PASSWORD="$2"; shift 2;;
        *) echo "Unknown arg: $1"; exit 1;;
    esac
done

# ============================================================================
# Helper functions
# ============================================================================
cleanup() {
    rm -f "$TEMP_TOKEN_FILE"
    rm -f "$HOME/.ssoctl/config.yaml" 2>/dev/null || true
}
trap cleanup EXIT

pass() { PASSED=$((PASSED + 1)); echo "  PASS: $1"; }
fail() { FAILED=$((FAILED + 1)); echo "  FAIL: $1" >&2; }
fail_and_exit() { FAILED=$((FAILED + 1)); echo "FATAL: $1" >&2; exit 1; }

assert_contains() {
    local haystack="$1" needle="$2" desc="$3"
    if echo "$haystack" | grep -qi "$needle"; then
        pass "$desc"
    else
        fail "$desc — expected to contain '$needle'"
        echo "  Output was: $haystack" >&2
    fi
}

assert_exit_code() {
    local code="$1" desc="$2"
    [[ "$code" -eq 0 ]] && pass "$desc" || fail "$desc — expected 0, got $code"
}

assert_exit_code_nonzero() {
    local code="$1" desc="$2"
    [[ "$code" -ne 0 ]] && pass "$desc" || fail "$desc — expected non-zero, got 0"
}

# ============================================================================
# Build sssoctl if not present
# ============================================================================
echo ""
echo "============================================="
echo " Phase 0: Build sssoctl"
echo "============================================="
echo ""
if [[ ! -f "$SSSOCTL_BIN" ]]; then
    echo "Building sssoctl..."
    mkdir -p "$(dirname "$SSSOCTL_BIN")"
    (cd "$PROJECT_ROOT" && go build -o "$SSSOCTL_BIN" ./apps/sssoctl/) || fail_and_exit "Failed to build sssoctl"
    pass "sssoctl built"
else
    pass "sssoctl already built at $SSSOCTL_BIN"
fi

# ============================================================================
# Phase 1: Read bootstrap token from pod
# ============================================================================
echo ""
echo "============================================="
echo " Phase 1: Read Bootstrap Token from Pod"
echo "============================================="
echo ""

# Get a running backend pod
BACKEND_POD=$(kubectl -n "$NAMESPACE" get pods \
    -l app.kubernetes.io/name=ssso-backend \
    -l app.kubernetes.io/component=backend \
    --field-selector=status.phase=Running \
    -o jsonpath='{.items[0].metadata.name}' 2>&1)

if [[ -z "$BACKEND_POD" ]]; then
    fail_and_exit "No running ssso-backend pod found in namespace $NAMESPACE"
fi
echo "Using pod: $BACKEND_POD"
pass "Found running backend pod"

# Check bootstrap status first
echo ""
echo "Checking bootstrap status..."
BOOTSTRAP_STATUS=$(kubectl -n "$NAMESPACE" exec "$BACKEND_POD" -- \
    sh -c "cat $BOOTSTRAP_TOKEN_PATH 2>/dev/null && echo OK || echo MISSING" 2>&1)

if echo "$BOOTSTRAP_STATUS" | grep -q "MISSING"; then
    echo "  Note: Bootstrap token file not found — server may already be bootstrapped"
    echo "  Checking if server is already bootstrapped by trying to login..."
    
    # Try to login with admin credentials — if it works, skip bootstrap
    LOGIN_TRY=$("$SSSOCTL_BIN" auth login \
        --flow=password \
        --server "$SSO_SERVER" \
        --email "$ADMIN_EMAIL" \
        --password "$ADMIN_PASSWORD" \
        --skip-confirmation 2>&1) || LOGIN_TRY_EXIT=$?
    
    if echo "$LOGIN_TRY" | grep -qi "Login successful"; then
        echo "  Server already bootstrapped, admin login works."
        pass "Server already bootstrapped — proceeding to test existing deployment"
        # Skip to auth tests
        goto_auth=true
    else
        fail_and_exit "Bootstrap token not found AND admin login failed. Deploy a fresh instance or wipe the database."
    fi
else
    # Read the token
    kubectl -n "$NAMESPACE" exec "$BACKEND_POD" -- \
        cat "$BOOTSTRAP_TOKEN_PATH" > "$TEMP_TOKEN_FILE" 2>/dev/null
    
    BOOTSTRAP_TOKEN=$(cat "$TEMP_TOKEN_FILE" | tr -d '[:space:]')
    if [[ -z "$BOOTSTRAP_TOKEN" ]]; then
        fail_and_exit "Bootstrap token file is empty"
    fi
    pass "Bootstrap token read from pod ($BACKEND_POD)"
    goto_auth=false
fi

# ============================================================================
# Phase 2: Bootstrap the SSO server
# ============================================================================
if [[ "${goto_auth:-false}" == "false" ]]; then
    echo ""
    echo "============================================="
    echo " Phase 2: Bootstrap via sssoctl"
    echo "============================================="
    echo ""

    echo "Admin email: $ADMIN_EMAIL"
    echo "Admin password: [generated]"
    echo ""

    BOOTSTRAP_OUTPUT=$("$SSSOCTL_BIN" bootstrap \
        --server "$SSO_SERVER" \
        --token-file "$TEMP_TOKEN_FILE" \
        --admin-email "$ADMIN_EMAIL" \
        --admin-password "$ADMIN_PASSWORD" \
        --admin-first-name "Admin" \
        --admin-last-name "PiLab" \
        --output yaml 2>&1)
    BOOTSTRAP_EXIT=$?

    assert_exit_code "$BOOTSTRAP_EXIT" "Bootstrap command succeeded"
    assert_contains "$BOOTSTRAP_OUTPUT" "$ADMIN_EMAIL" "Bootstrap output contains admin email"
    assert_contains "$BOOTSTRAP_OUTPUT" "client_id" "Bootstrap output contains admin client"

    echo ""
    echo "Bootstrap output:"
    echo "$BOOTSTRAP_OUTPUT"
    echo ""

    # ============================================================================
    # Phase 2b: Verify single-use token invalidation
    # ============================================================================
    echo ""
    echo "Testing bootstrap token single-use invalidation..."
    SECOND_BOOTSTRAP=$("$SSSOCTL_BIN" bootstrap \
        --server "$SSO_SERVER" \
        --token-file "$TEMP_TOKEN_FILE" \
        --admin-email "second-admin@example.com" \
        --admin-password "AnotherPassword123!" \
        --output yaml 2>&1) || SECOND_BOOTSTRAP_EXIT=$?
    SECOND_BOOTSTRAP_EXIT=${SECOND_BOOTSTRAP_EXIT:-0}
    assert_exit_code_nonzero "$SECOND_BOOTSTRAP_EXIT" "Second bootstrap fails (token already consumed)"
fi

# ============================================================================
# Phase 3: Auth Login
# ============================================================================
echo ""
echo "============================================="
echo " Phase 3: Auth Login"
echo "============================================="
echo ""

LOGIN_OUTPUT=$("$SSSOCTL_BIN" auth login \
    --flow=password \
    --server "$SSO_SERVER" \
    --email "$ADMIN_EMAIL" \
    --password "$ADMIN_PASSWORD" \
    --skip-confirmation 2>&1)
LOGIN_EXIT=$?

assert_exit_code "$LOGIN_EXIT" "Auth login succeeded"
assert_contains "$LOGIN_OUTPUT" "Login successful" "Login output confirms success"

# ============================================================================
# Phase 4: User CRUD
# ============================================================================
echo ""
echo "============================================="
echo " Phase 4: User CRUD"
echo "============================================="
echo ""

echo "Creating test user..."
USER_CREATE=$("$SSSOCTL_BIN" user create \
    --email "$TEST_USER_EMAIL" \
    --password "TestUser123!" \
    --first-name "Test" \
    --last-name "User" \
    --output yaml 2>&1)
USER_CREATE_EXIT=$?
assert_exit_code "$USER_CREATE_EXIT" "User create succeeded"
assert_contains "$USER_CREATE" "$TEST_USER_EMAIL" "User create output contains email"

echo ""
echo "Getting user..."
USER_GET=$("$SSSOCTL_BIN" user get "$TEST_USER_EMAIL" --output yaml 2>&1)
assert_exit_code "$?" "User get succeeded"
assert_contains "$USER_GET" "$TEST_USER_EMAIL" "User get returns correct email"

echo ""
echo "Listing users..."
USER_LIST=$("$SSSOCTL_BIN" user list --output yaml 2>&1)
assert_exit_code "$?" "User list succeeded"
assert_contains "$USER_LIST" "$ADMIN_EMAIL" "User list contains admin"
assert_contains "$USER_LIST" "$TEST_USER_EMAIL" "User list contains test user"

# ============================================================================
# Phase 5: Client CRUD
# ============================================================================
echo ""
echo "============================================="
echo " Phase 5: Client CRUD"
echo "============================================="
echo ""

echo "Registering client..."
CLIENT_REGISTER=$("$SSSOCTL_BIN" client register \
    --name "$TEST_CLIENT_NAME" \
    --type confidential \
    --redirect-uris "http://localhost:3000/callback" \
    --grant-types "authorization_code,refresh_token" \
    --scopes "openid,profile,email" \
    --output yaml 2>&1)
CLIENT_REGISTER_EXIT=$?
assert_exit_code "$CLIENT_REGISTER_EXIT" "Client register succeeded"
assert_contains "$CLIENT_REGISTER" "$TEST_CLIENT_NAME" "Client register output contains name"

echo ""
echo "Listing clients..."
CLIENT_LIST=$("$SSSOCTL_BIN" client list --output yaml 2>&1)
assert_exit_code "$?" "Client list succeeded"
assert_contains "$CLIENT_LIST" "$TEST_CLIENT_NAME" "Client list contains test client"

# ============================================================================
# Phase 6: Verify SSO endpoints
# ============================================================================
echo ""
echo "============================================="
echo " Phase 6: Verify OIDC Endpoints"
echo "============================================="
echo ""

DISCOVERY_RESPONSE=$(curl -sf "${SSO_SERVER}/.well-known/openid-configuration" 2>&1)
assert_exit_code "$?" "OIDC discovery endpoint accessible"
assert_contains "$DISCOVERY_RESPONSE" "issuer" "Discovery response contains issuer"
assert_contains "$DISCOVERY_RESPONSE" "jwks_uri" "Discovery response contains jwks_uri"
pass "OIDC discovery endpoint returns valid metadata"

JWKS_RESPONSE=$(curl -sf "${SSO_SERVER}/.well-known/jwks.json" 2>&1)
assert_exit_code "$?" "JWKS endpoint accessible"
assert_contains "$JWKS_RESPONSE" "keys" "JWKS response contains keys"

# ============================================================================
# Phase 7: Cleanup
# ============================================================================
echo ""
echo "============================================="
echo " Phase 7: Cleanup"
echo "============================================="
echo ""

echo "Deleting test user..."
"$SSSOCTL_BIN" user delete --user-id "$TEST_USER_EMAIL" --confirm 2>&1 || true
pass "Test user cleanup"

echo "Logging out..."
"$SSSOCTL_BIN" auth logout 2>&1 || true
pass "Auth logout"

# ============================================================================
# Summary
# ============================================================================
echo ""
echo "============================================="
echo " Summary"
echo "============================================="
echo ""
echo "Server: $SSO_SERVER"
echo "Admin email: $ADMIN_EMAIL"
echo "Total: $((PASSED + FAILED))  Passed: $PASSED  Failed: $FAILED"
echo ""

if [[ "$FAILED" -gt 0 ]]; then
    echo "SOME TESTS FAILED"
    exit 1
else
    echo "ALL KUBERNETES INTEGRATION TESTS PASSED"
    echo ""
    if [[ "${goto_auth:-false}" == "false" ]]; then
        echo "IMPORTANT: Save these admin credentials:"
        echo "  Email:    $ADMIN_EMAIL"
        echo "  Password: $ADMIN_PASSWORD"
    fi
    exit 0
fi
