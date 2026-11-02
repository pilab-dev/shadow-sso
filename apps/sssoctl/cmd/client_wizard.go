package cmd

import (
	"fmt"
	"net/url"
	"strings"
)

// clientWizardResult is the collected client registration form.
type clientWizardResult struct {
	Name                    string
	Description             string
	Type                    string
	RedirectURIs            []string
	PostLogoutRedirectURIs  []string
	GrantTypes              []string
	Scopes                  []string
	TokenEndpointAuthMethod string
	RequireConsent          bool
	Contacts                []string
}

func splitCommaList(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func validateURLList(value string) error {
	for _, raw := range splitCommaList(value) {
		u, err := url.Parse(raw)
		if err != nil || u.Scheme == "" || u.Host == "" {
			return fmt.Errorf("invalid URL %q (expected scheme://host/path)", raw)
		}
		if strings.Contains(raw, " ") {
			return fmt.Errorf("URL %q contains a space", raw)
		}
	}
	return nil
}

// runClientWizard guides the operator through client registration. Fields that
// were supplied as flags are prefilled.
func runClientWizard(initial clientWizardResult) (clientWizardResult, error) {
	fields := []formField{
		{
			key: "name", label: "Client name", kind: formText, required: true,
			help: "Human-readable name shown on consent screens.",
		},
		{
			key: "description", label: "Description", kind: formText,
			help: "Optional. Leave empty to skip.",
		},
		{
			key: "type", label: "Client type", kind: formSelect, required: true,
			options:      []string{"confidential", "public"},
			defaultValue: "confidential",
			help:         "Confidential clients keep a secret; public clients (SPA, mobile) use PKCE.",
		},
		{
			key: "redirect_uris", label: "Redirect URIs", kind: formText,
			help:     "Comma separated. Required for authorization_code. Example: https://app.example.com/callback",
			validate: validateURLList,
		},
		{
			key: "post_logout_redirect_uris", label: "Post-logout redirect URIs", kind: formText,
			help:     "Comma separated. Optional.",
			validate: validateURLList,
		},
		{
			key: "grant_types", label: "Grant types", kind: formMulti, required: true,
			options: []string{
				"authorization_code",
				"refresh_token",
				"client_credentials",
				"implicit",
				"urn:ietf:params:oauth:grant-type:device_code",
			},
			defaultValue: "authorization_code,refresh_token",
			help:         "Space toggles, enter confirms.",
		},
		{
			key: "scopes", label: "Allowed scopes", kind: formText,
			defaultValue: "openid,profile,email,offline_access",
			help:         "Comma separated.",
		},
		{
			key: "token_endpoint_auth_method", label: "Token endpoint auth", kind: formSelect,
			options:      []string{"(server default)", "client_secret_basic", "client_secret_post", "none"},
			defaultValue: "(server default)",
			help:         "Confidential clients normally use client_secret_basic.",
		},
		{
			key: "require_consent", label: "Require consent", kind: formBool,
			defaultValue: "false",
			help:         "Ask the user to approve scopes on every new authorization.",
		},
		{
			key: "contacts", label: "Contacts", kind: formText,
			help: "Comma separated emails. Optional.",
		},
	}

	initialValues := map[string]string{
		"name":                       initial.Name,
		"description":                initial.Description,
		"type":                       initial.Type,
		"redirect_uris":              strings.Join(initial.RedirectURIs, ","),
		"post_logout_redirect_uris":  strings.Join(initial.PostLogoutRedirectURIs, ","),
		"grant_types":                strings.Join(initial.GrantTypes, ","),
		"scopes":                     strings.Join(initial.Scopes, ","),
		"token_endpoint_auth_method": initial.TokenEndpointAuthMethod,
		"require_consent":            fmt.Sprintf("%t", initial.RequireConsent),
		"contacts":                   strings.Join(initial.Contacts, ","),
	}
	if initial.Type == "" {
		initialValues["type"] = "confidential"
	}
	if len(initial.GrantTypes) == 0 {
		initialValues["grant_types"] = "authorization_code,refresh_token"
	}
	if len(initial.Scopes) == 0 {
		initialValues["scopes"] = "openid,profile,email,offline_access"
	}
	if initial.TokenEndpointAuthMethod == "" {
		initialValues["token_endpoint_auth_method"] = "(server default)"
	}

	values, err := runForm("Client registration", fields, initialValues)
	if err != nil {
		return clientWizardResult{}, err
	}

	result := clientWizardResult{
		Name:                    values["name"],
		Description:             values["description"],
		Type:                    values["type"],
		RedirectURIs:            splitCommaList(values["redirect_uris"]),
		PostLogoutRedirectURIs:  splitCommaList(values["post_logout_redirect_uris"]),
		GrantTypes:              splitCommaList(values["grant_types"]),
		Scopes:                  splitCommaList(values["scopes"]),
		TokenEndpointAuthMethod: values["token_endpoint_auth_method"],
		RequireConsent:          values["require_consent"] == "true",
		Contacts:                splitCommaList(values["contacts"]),
	}
	if result.TokenEndpointAuthMethod == "(server default)" {
		result.TokenEndpointAuthMethod = ""
	}
	if result.Type == "public" && result.TokenEndpointAuthMethod == "" {
		result.TokenEndpointAuthMethod = "none"
	}
	return result, nil
}
