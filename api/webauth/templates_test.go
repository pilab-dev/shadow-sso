package webauth

import (
	"bytes"
	"html"
	"html/template"
	"path/filepath"
	"testing"
)

func TestTemplatesParse(t *testing.T) {
	// Construct the path to the templates directory
	templatesDir := filepath.Join("templates", "*.html")

	// Parse all templates
	tmpl, err := template.ParseGlob(templatesDir)
	if err != nil {
		t.Fatalf("Failed to parse templates: %v", err)
	}

	// List of expected templates (files end with .html)
	expectedTemplates := []string{
		"base.html",
		"login.html",
		"consent.html",
		"mfa.html",
		"merge.html",
		"error.html",
	}

	// Check that all expected templates are present
	for _, name := range expectedTemplates {
		if tmpl.Lookup(name) == nil {
			t.Errorf("Template %q not found", name)
		}
	}

	t.Logf("Successfully parsed %d templates", len(tmpl.Templates()))
}

func TestLoginTemplate(t *testing.T) {
	templatesDir := filepath.Join("templates", "*.html")
	tmpl, err := template.ParseGlob(templatesDir)
	if err != nil {
		t.Fatalf("Failed to parse templates: %v", err)
	}

	// Test data - use PascalCase for login template, lowercase for base template
	data := map[string]interface{}{
		"BrandName":  "Test Org",
		"BrandLogo":  "https://example.com/logo.png",
		"BrandColor": "#007bff",
		"brand_name":  "Test Org",
		"brand_logo":  "https://example.com/logo.png",
		"brand_color": "#007bff",
		"FlowID":     "test-flow-123",
		"CSRFToken":  "test-csrf-token",
		"Error":      "Invalid credentials",
		"Providers": []map[string]string{
			{"Name": "google"},
			{"Name": "github"},
			{"Name": "apple"},
		},
	}

	// Execute the template into a buffer
	var buf bytes.Buffer
	err = tmpl.ExecuteTemplate(&buf, "login.html", data)
	if err != nil {
		t.Fatalf("Failed to execute login template: %v", err)
	}

	// Assert rendered content contains expected values
	output := buf.String()
	if !contains(output, "Test Org") {
		t.Errorf("Expected brand name in output")
	}
	if !contains(output, "test-flow-123") {
		t.Errorf("Expected flow ID in output")
	}
	if !contains(output, "test-csrf-token") {
		t.Errorf("Expected CSRF token in output")
	}
	if !contains(output, "Invalid credentials") {
		t.Errorf("Expected error message in output")
	}
	if !contains(output, "google") || !contains(output, "github") || !contains(output, "apple") {
		t.Errorf("Expected provider names in output")
	}
}

func TestConsentTemplate(t *testing.T) {
	templatesDir := filepath.Join("templates", "*.html")
	tmpl, err := template.ParseGlob(templatesDir)
	if err != nil {
		t.Fatalf("Failed to parse templates: %v", err)
	}

	// Test data - use PascalCase for consent template, lowercase for base template
	data := map[string]interface{}{
		"BrandName":        "Test Org",
		"BrandLogo":        "https://example.com/logo.png",
		"BrandColor":       "#007bff",
		"brand_name":       "Test Org",
		"brand_logo":       "https://example.com/logo.png",
		"brand_color":      "#007bff",
		"FlowID":           "test-flow-123",
		"CSRFToken":        "test-csrf-token",
		"ClientName":       "My App",
		"ClientLogo":       "https://example.com/app-logo.png",
		"ClientDescription": "A sample application",
		"Scopes": []map[string]string{
			{"Description": "Read your profile"},
			{"Description": "Access your email"},
		},
		"RedirectURI": "https://example.com/callback",
	}

	var buf bytes.Buffer
	err = tmpl.ExecuteTemplate(&buf, "consent.html", data)
	if err != nil {
		t.Fatalf("Failed to execute consent template: %v", err)
	}

	output := buf.String()
	if !contains(output, "Test Org") {
		t.Errorf("Expected brand name in output")
	}
	if !contains(output, "test-flow-123") {
		t.Errorf("Expected flow ID in output")
	}
	if !contains(output, "test-csrf-token") {
		t.Errorf("Expected CSRF token in output")
	}
	if !contains(output, "My App") {
		t.Errorf("Expected client name in output")
	}
	if !contains(output, "A sample application") {
		t.Errorf("Expected client description in output")
	}
	if !contains(output, "Read your profile") || !contains(output, "Access your email") {
		t.Errorf("Expected scope descriptions in output")
	}
	if !contains(output, "Allow Access") || !contains(output, "Deny") {
		t.Errorf("Expected approve/deny buttons in output")
	}
}

func TestMFATemplate(t *testing.T) {
	templatesDir := filepath.Join("templates", "*.html")
	tmpl, err := template.ParseGlob(templatesDir)
	if err != nil {
		t.Fatalf("Failed to parse templates: %v", err)
	}

	// Test data - use PascalCase for MFA template, lowercase for base template
	data := map[string]interface{}{
		"BrandName":  "Test Org",
		"BrandLogo":  "https://example.com/logo.png",
		"BrandColor": "#007bff",
		"brand_name":  "Test Org",
		"brand_logo":  "https://example.com/logo.png",
		"brand_color": "#007bff",
		"FlowID":     "test-flow-123",
		"CSRFToken":  "test-csrf-token",
		"Error":      "Invalid code",
	}

	var buf bytes.Buffer
	err = tmpl.ExecuteTemplate(&buf, "mfa.html", data)
	if err != nil {
		t.Fatalf("Failed to execute MFA template: %v", err)
	}

	output := buf.String()
	if !contains(output, "Test Org") {
		t.Errorf("Expected brand name in output")
	}
	if !contains(output, "test-flow-123") {
		t.Errorf("Expected flow ID in output")
	}
	if !contains(output, "test-csrf-token") {
		t.Errorf("Expected CSRF token in output")
	}
	if !contains(output, "Invalid code") {
		t.Errorf("Expected error message in output")
	}
	if !contains(output, "Verification Code") {
		t.Errorf("Expected MFA form label in output")
	}
	if !contains(output, "Verify") {
		t.Errorf("Expected verify button in output")
	}
}

func TestErrorTemplate(t *testing.T) {
	templatesDir := filepath.Join("templates", "*.html")
	tmpl, err := template.ParseGlob(templatesDir)
	if err != nil {
		t.Fatalf("Failed to parse templates: %v", err)
	}

	// Test data - use PascalCase for error template, lowercase for base template
	data := map[string]interface{}{
		"BrandName":  "Test Org",
		"BrandLogo":  "https://example.com/logo.png",
		"BrandColor": "#007bff",
		"brand_name":  "Test Org",
		"brand_logo":  "https://example.com/logo.png",
		"brand_color": "#007bff",
		"Message":    "Access Denied",
		"Detail":     "You don't have permission to access this resource.",
		"LoginURL":   "/login",
		"RequestID":  "req-123-abc",
	}

	var buf bytes.Buffer
	err = tmpl.ExecuteTemplate(&buf, "error.html", data)
	if err != nil {
		t.Fatalf("Failed to execute error template: %v", err)
	}

	output := html.UnescapeString(buf.String())
	if !contains(output, "Test Org") {
		t.Errorf("Expected brand name in output")
	}
	if !contains(output, "Access Denied") {
		t.Errorf("Expected error message in output")
	}
	if !contains(output, "You don't have permission") {
		t.Errorf("Expected error detail in output")
	}
	if !contains(output, "Back to Sign In") {
		t.Errorf("Expected back link in output")
	}
	if !contains(output, "Go Back") {
		t.Errorf("Expected go back button in output")
	}
	if !contains(output, "req-123-abc") {
		t.Errorf("Expected request ID in output")
	}
}

// contains checks if a string contains a substring (case-sensitive)
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > len(substr) && (s[:len(substr)] == substr || s[len(s)-len(substr):] == substr || containsInternal(s, substr)))
}

func containsInternal(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}