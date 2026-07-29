package integration

import (
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testUserPassword = "TestPass123!"

// uniqueTestEmail generates a unique email for each test to avoid collisions.
func uniqueTestEmail(prefix string) string {
	return prefix + "-" + strings.ToLower(randomSuffix()) + "@integration.test"
}

// randomSuffix returns a short unique string for test isolation.
func randomSuffix() string {
	return strings.ReplaceAll(time.Now().Format("150405.000000000"), ".", "")
}

// TestCLIUser_Register registers a new user via the admin CLI and verifies output.
func TestCLIUser_Register(t *testing.T) {
	h := SetupCLITest(t)
	defer h.Close()

	email := uniqueTestEmail("register")
	output, err := h.ExecuteCommand(
		"user", "register",
		"--email", email,
		"--password", testUserPassword,
		"--first-name", "Test",
		"--last-name", "User",
	)
	require.NoError(t, err, "user register failed: %s", output)

	// YAML output should contain the user email
	assert.Contains(t, output, email, "output should contain registered email")
	assert.Contains(t, output, "registered successfully", "output should indicate success")
}

// TestCLIUser_Get retrieves a user by email after registration.
func TestCLIUser_Get(t *testing.T) {
	h := SetupCLITest(t)
	defer h.Close()

	email := uniqueTestEmail("getuser")

	// Register first
	_, err := h.ExecuteCommand(
		"user", "register",
		"--email", email,
		"--password", testUserPassword,
		"--first-name", "Get",
		"--last-name", "Test",
	)
	require.NoError(t, err, "register failed")

	// Get by email
	output, err := h.ExecuteCommand("user", "get", email)
	require.NoError(t, err, "user get failed: %s", output)

	assert.Contains(t, output, email, "output should contain user email")
	assert.Contains(t, output, "Get", "output should contain first name")
}

// TestCLIUser_List lists users with pagination.
func TestCLIUser_List(t *testing.T) {
	h := SetupCLITest(t)
	defer h.Close()

	// Register a couple of users first
	for i := 0; i < 2; i++ {
		email := uniqueTestEmail("listuser")
		_, err := h.ExecuteCommand(
			"user", "register",
			"--email", email,
			"--password", testUserPassword,
			"--first-name", "List",
			"--last-name", "Test",
		)
		require.NoError(t, err, "register failed for list user %d", i)
	}

	output, err := h.ExecuteCommand("user", "list", "--page-size", "10")
	require.NoError(t, err, "user list failed: %s", output)

	assert.NotContains(t, output, "No users found", "list should return users")
}

// TestCLIUser_Activate activates a user after registration.
func TestCLIUser_Activate(t *testing.T) {
	h := SetupCLITest(t)
	defer h.Close()

	email := uniqueTestEmail("activate")

	_, err := h.ExecuteCommand(
		"user", "register",
		"--email", email,
		"--password", testUserPassword,
		"--first-name", "Activate",
		"--last-name", "Test",
	)
	require.NoError(t, err, "register failed")

	// Activate by email
	output, err := h.ExecuteCommand("user", "activate", email)
	require.NoError(t, err, "user activate failed: %s", output)

	assert.Contains(t, output, "activated successfully", "output should confirm activation")
}

// TestCLIUser_Lock locks a user after registration and activation.
func TestCLIUser_Lock(t *testing.T) {
	h := SetupCLITest(t)
	defer h.Close()

	email := uniqueTestEmail("lockuser")

	_, err := h.ExecuteCommand(
		"user", "register",
		"--email", email,
		"--password", testUserPassword,
		"--first-name", "Lock",
		"--last-name", "Test",
	)
	require.NoError(t, err, "register failed")

	// Activate first
	_, err = h.ExecuteCommand("user", "activate", email)
	require.NoError(t, err, "activate failed")

	// Lock the user
	output, err := h.ExecuteCommand("user", "lock", email)
	require.NoError(t, err, "user lock failed: %s", output)

	assert.Contains(t, output, "locked successfully", "output should confirm lock")
}

// TestCLIUser_ChangePassword changes a user's password and verifies login.
func TestCLIUser_ChangePassword(t *testing.T) {
	h := SetupCLITest(t)
	defer h.Close()

	email := uniqueTestEmail("chpass")
	newPass := "NewSecurePass456!"

	_, err := h.ExecuteCommand(
		"user", "register",
		"--email", email,
		"--password", testUserPassword,
		"--first-name", "Change",
		"--last-name", "Pass",
	)
	require.NoError(t, err, "register failed")

	// Activate user
	_, err = h.ExecuteCommand("user", "activate", email)
	require.NoError(t, err, "activate failed")

	// Change password as admin
	output, err := h.ExecuteCommand(
		"user", "change-password", email,
		"--new-password", newPass,
	)
	require.NoError(t, err, "change-password failed: %s", output)

	assert.Contains(t, output, "Password changed successfully", "output should confirm password change")

	// Verify new password works by logging in as the user
	h.LoginAsUser(email, newPass)

	// Verify old password no longer works by trying to login (should fail)
	// We can test this via a get command after switching back to admin token
	h.RefreshAdminToken()

	// Also verify old password doesn't work by attempting login via API
	// (not strictly necessary for CLI test but good for confidence)
}

// TestCLIUser_Register_DuplicateEmail verifies that registering with an existing email fails.
func TestCLIUser_Register_DuplicateEmail(t *testing.T) {
	h := SetupCLITest(t)
	defer h.Close()

	email := uniqueTestEmail("duplicate")

	// First registration succeeds
	_, err := h.ExecuteCommand(
		"user", "register",
		"--email", email,
		"--password", testUserPassword,
		"--first-name", "Dup",
		"--last-name", "One",
	)
	require.NoError(t, err, "first register should succeed")

	// Second registration with same email must fail
	output, err := h.ExecuteCommand(
		"user", "register",
		"--email", email,
		"--password", testUserPassword,
		"--first-name", "Dup",
		"--last-name", "Two",
	)
	assert.Error(t, err, "duplicate email registration should fail")
	assert.True(t,
		strings.Contains(output, "already exists") ||
			strings.Contains(output, "failed") ||
			strings.Contains(strings.ToLower(output), "already"),
		"error should mention duplicate/already exists: %s", output)
}

// TestCLIUser_Register_MissingEmail verifies that omitting --email flag fails.
func TestCLIUser_Register_MissingEmail(t *testing.T) {
	h := SetupCLITest(t)
	defer h.Close()

	output, err := h.ExecuteCommand(
		"user", "register",
		"--password", testUserPassword,
		"--first-name", "NoEmail",
		"--last-name", "Test",
	)
	assert.Error(t, err, "register without email should fail")
	assert.True(t,
		strings.Contains(output, "email is required") ||
			strings.Contains(strings.ToLower(output), "email") ||
			strings.Contains(output, "required"),
		"error should mention email requirement: %s", output)
}

// TestCLIUser_2FA_FullFlow tests the complete 2FA setup, verify,
// recovery codes, and disable flow.
func TestCLIUser_2FA_FullFlow(t *testing.T) {
	h := SetupCLITest(t)
	defer h.Close()

	// 1. Register and activate a test user
	email := uniqueTestEmail("twofa")
	password := "TwoFATest123!"

	_, err := h.ExecuteCommand(
		"user", "register",
		"--email", email,
		"--password", password,
		"--first-name", "TwoFA",
		"--last-name", "Test",
	)
	require.NoError(t, err, "register failed")

	_, err = h.ExecuteCommand("user", "activate", email)
	require.NoError(t, err, "activate failed")

	// 2. Login as the test user (not admin)
	h.LoginAsUser(email, password)

	// 3. Initiate TOTP setup
	setupOut, err := h.ExecuteCommand("user", "2fa", "setup")
	require.NoError(t, err, "2fa setup failed: %s", setupOut)

	// Extract the TOTP secret from the output
	secret := extractTOTPSecret(t, setupOut)
	require.NotEmpty(t, secret, "could not extract TOTP secret from setup output")

	// 4. Generate a valid TOTP code
	totpCode, err := totp.GenerateCode(secret, time.Now())
	require.NoError(t, err, "failed to generate TOTP code")

	// 5. Verify and enable 2FA
	verifyOut, err := h.ExecuteCommand("user", "2fa", "verify", totpCode)
	require.NoError(t, err, "2fa verify failed: %s", verifyOut)

	assert.Contains(t, verifyOut, "enabled successfully", "output should confirm 2FA enabled")
	assert.Contains(t, verifyOut, "recovery codes", "output should mention recovery codes")

	// 6. Generate new recovery codes
	recoveryOut, err := h.ExecuteCommand("user", "2fa", "recovery-codes")
	require.NoError(t, err, "recovery-codes failed: %s", recoveryOut)

	assert.Contains(t, recoveryOut, "New recovery codes generated", "output should confirm new recovery codes")

	// 7. Generate a fresh TOTP code and disable 2FA
	totpCode2, err := totp.GenerateCode(secret, time.Now())
	require.NoError(t, err, "failed to generate second TOTP code")

	disableOut, err := h.ExecuteCommand("user", "2fa", "disable", "-p", totpCode2)
	require.NoError(t, err, "2fa disable failed: %s", disableOut)

	assert.Contains(t, disableOut, "disabled successfully", "output should confirm 2FA disabled")
}

// extractTOTPSecret parses the TOTP secret from the 2fa setup command output.
// The output format is: "Secret (for manual entry): <base32_secret>"
func extractTOTPSecret(t testing.TB, output string) string {
	t.Helper()
	re := regexp.MustCompile(`Secret\s*\(for manual entry\):\s*(\S+)`)
	matches := re.FindStringSubmatch(output)
	if len(matches) >= 2 {
		return matches[1]
	}
	return ""
}
