package webauth

import (
	"html/template"
	"os"
	"path/filepath"
	"testing"
)

func TestTemplatesParse(t *testing.T) {
	// Get the directory where this test file is located
	_, err := os.Getwd()
	if err != nil {
		t.Fatalf("Failed to get working directory: %v", err)
	}

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

	// Test data
	data := map[string]interface{}{
		"brand_name":  "Test Org",
		"brand_logo":  "https://example.com/logo.png",
		"brand_color": "#007bff",
		"flow_id":     "test-flow-123",
		"csrf_token":  "test-csrf-token",
		"error":       "Invalid credentials",
		"providers": []map[string]string{
			{"Name": "google"},
			{"Name": "github"},
			{"Name": "apple"},
		},
	}

	// Execute the template
	err = tmpl.ExecuteTemplate(os.Stdout, "login.html", data)
	if err != nil {
		t.Fatalf("Failed to execute login template: %v", err)
	}
}

func TestConsentTemplate(t *testing.T) {
	templatesDir := filepath.Join("templates", "*.html")
	tmpl, err := template.ParseGlob(templatesDir)
	if err != nil {
		t.Fatalf("Failed to parse templates: %v", err)
	}

	// Test data
	data := map[string]interface{}{
		"brand_name":       "Test Org",
		"brand_logo":       "https://example.com/logo.png",
		"brand_color":      "#007bff",
		"flow_id":          "test-flow-123",
		"csrf_token":       "test-csrf-token",
		"client_name":      "My App",
		"client_logo":      "https://example.com/app-logo.png",
		"client_description": "A sample application",
		"scopes": []map[string]string{
			{"Description": "Read your profile"},
			{"Description": "Access your email"},
		},
	}

	// Execute the template
	err = tmpl.ExecuteTemplate(os.Stdout, "consent.html", data)
	if err != nil {
		t.Fatalf("Failed to execute consent template: %v", err)
	}
}

func TestMFATemplate(t *testing.T) {
	templatesDir := filepath.Join("templates", "*.html")
	tmpl, err := template.ParseGlob(templatesDir)
	if err != nil {
		t.Fatalf("Failed to parse templates: %v", err)
	}

	// Test data
	data := map[string]interface{}{
		"brand_name":  "Test Org",
		"brand_logo":  "https://example.com/logo.png",
		"brand_color": "#007bff",
		"flow_id":     "test-flow-123",
		"csrf_token":  "test-csrf-token",
		"session_id":  "test-session-456",
		"error":       "Invalid code",
	}

	// Execute the template
	err = tmpl.ExecuteTemplate(os.Stdout, "mfa.html", data)
	if err != nil {
		t.Fatalf("Failed to execute MFA template: %v", err)
	}
}

func TestErrorTemplate(t *testing.T) {
	templatesDir := filepath.Join("templates", "*.html")
	tmpl, err := template.ParseGlob(templatesDir)
	if err != nil {
		t.Fatalf("Failed to parse templates: %v", err)
	}

	// Test data
	data := map[string]interface{}{
		"brand_name":  "Test Org",
		"brand_logo":  "https://example.com/logo.png",
		"brand_color": "#007bff",
		"message":     "Access Denied",
		"detail":      "You don't have permission to access this resource.",
		"request_id":  "req-123-abc",
	}

	// Execute the template
	err = tmpl.ExecuteTemplate(os.Stdout, "error.html", data)
	if err != nil {
		t.Fatalf("Failed to execute error template: %v", err)
	}
}
