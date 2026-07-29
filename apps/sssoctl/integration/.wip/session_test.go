package integration

import (
	"strings"
	"testing"

	ssoctlconfig "github.com/pilab-dev/shadow-sso/apps/sssoctl/cmd/config"
)

func TestCLISession_List(t *testing.T) {
	h := SetupCLITest(t, cliTestEmail, cliTestPassword)
	defer h.Cleanup(t)
	loginViaAPI(t, h)

	out, err := ExecuteCommand(t, h.RootCmd, "session", "list")
	if err != nil {
		t.Fatalf("session list: %v\n%s", err, out)
	}
	if strings.Contains(out, "No active sessions found") {
		t.Error("expected active sessions after login")
	}
	t.Logf("sessions:\n%s", out)
}

func TestCLISession_Clear(t *testing.T) {
	h := SetupCLITest(t, cliTestEmail, cliTestPassword)
	defer h.Cleanup(t)
	loginViaAPI(t, h)

	listOut, _ := ExecuteCommand(t, h.RootCmd, "session", "list")
	if strings.Contains(listOut, "No active sessions found") {
		t.Skip("no sessions to clear")
	}

	clearOut, err := ExecuteCommand(t, h.RootCmd, "session", "clear", "--all")
	if err != nil {
		t.Fatalf("session clear --all: %v\n%s", err, clearOut)
	}
	if !strings.Contains(clearOut, "cleared successfully") {
		t.Errorf("expected 'cleared successfully':\n%s", clearOut)
	}
}

func TestCLISession_Clear_NoSessions(t *testing.T) {
	h := SetupCLITest(t, cliTestEmail, cliTestPassword)
	defer h.Cleanup(t)
	loginViaAPI(t, h)

	ctx := ssoctlconfig.GlobalConfig.Contexts["test"]
	if ctx == nil {
		t.Fatal("context 'test' not found")
	}
	ctx.UserAuthToken = ""

	out, err := ExecuteCommand(t, h.RootCmd, "session", "clear", "--all")
	if err == nil {
		t.Errorf("expected error without auth, got:\n%s", out)
	}
	t.Logf("no-auth clear (expected error):\n%s", out)
}
