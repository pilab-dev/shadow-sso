package integration

import (
	"net/http"
	"testing"

	"github.com/pilab-dev/shadow-sso/apps/ssso/config"
)

func TestHarness_StartAndStop(t *testing.T) {
	srv, provider, addr := StartTestServer(t)
	if srv == nil {
		return // skipped (MongoDB not available)
	}
	defer StopTestServer(t, srv, provider)

	// Verify health endpoint
	resp, err := http.Get(addr + "/healthz")
	if err != nil {
		t.Fatalf("Health check failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected 200, got %d", resp.StatusCode)
	}
}

func TestHarness_WithAdminBootstrap(t *testing.T) {
	srv, provider, addr := StartTestServer(t, func(cfg *config.Config) {
		cfg.InitialAdminEnabled = true
		cfg.InitialAdminEmail = "admin@test.com"
		cfg.InitialAdminPassword = "test-password-123!"
		cfg.InitialAdminFirstName = "Admin"
		cfg.InitialAdminLastName = "User"
	})
	if srv == nil {
		return // skipped
	}
	defer StopTestServer(t, srv, provider)

	// Verify the server is alive after bootstrap
	resp, err := http.Get(addr + "/healthz")
	if err != nil {
		t.Fatalf("Health check failed after bootstrap: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected 200, got %d", resp.StatusCode)
	}
}
