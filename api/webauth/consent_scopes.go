package webauth

import "strings"

// scopeInfo is the user-facing description of an OAuth/OIDC scope.
type scopeInfo struct {
	Title       string
	Description string
}

var knownScopes = map[string]scopeInfo{
	"openid":         {"Sign you in", "Verify your identity and give the application a stable identifier for your account."},
	"profile":        {"Your profile", "See your name, username, picture and other basic profile details."},
	"email":          {"Your email address", "See your email address and whether it has been verified."},
	"address":        {"Your address", "See your postal address."},
	"phone":          {"Your phone number", "See your phone number and whether it has been verified."},
	"offline_access": {"Stay signed in", "Keep access to your account when you are not using the application."},
}

// requiredScopes cannot be unchecked on the consent screen.
var requiredScopes = map[string]bool{"openid": true}

// consentScope is a scope row rendered on the consent screen.
type consentScope struct {
	Name        string
	Title       string
	Description string
	Required    bool
}

func describeScopes(scopes []string) []consentScope {
	out := make([]consentScope, 0, len(scopes))
	for _, s := range scopes {
		info, ok := knownScopes[s]
		if !ok {
			info = scopeInfo{Title: s, Description: "Access granted by this application's custom permission."}
		}
		out = append(out, consentScope{Name: s, Title: info.Title, Description: info.Description, Required: requiredScopes[s]})
	}
	return out
}

// grantedScopes narrows the requested scopes to those the user left checked. Required scopes
// are always kept and scopes that were never requested are ignored.
func grantedScopes(requested string, selected []string) []string {
	chosen := make(map[string]bool, len(selected))
	for _, s := range selected {
		chosen[s] = true
	}
	var granted []string
	for _, s := range strings.Fields(requested) {
		if chosen[s] || requiredScopes[s] {
			granted = append(granted, s)
		}
	}
	return granted
}
