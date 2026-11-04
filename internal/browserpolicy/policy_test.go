package browserpolicy

import (
	"testing"

	"github.com/pilab-dev/shadow-sso/domain"
)

const (
	oldChrome = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.0.0 Safari/537.36"
	newChrome = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
	oldSafari = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Safari/605.1.15"
	curlUA    = "curl/8.7.1"
	botUA     = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
)

func TestEvaluate(t *testing.T) {
	enabled := func(p domain.BrowserPolicy) *domain.BrowserPolicy {
		p.Enabled = true
		return &p
	}

	tests := []struct {
		name        string
		ua          string
		policy      *domain.BrowserPolicy
		wantBlock   bool
		wantReason  string
		wantAllowed bool
	}{
		{name: "nil policy allows", ua: oldChrome, policy: nil, wantReason: ReasonDisabled, wantAllowed: true},
		{name: "disabled allows", ua: oldChrome, policy: &domain.BrowserPolicy{Enabled: false}, wantReason: ReasonDisabled, wantAllowed: true},
		{
			name: "outdated chrome blocks", ua: oldChrome,
			policy:    enabled(domain.BrowserPolicy{Enforcement: "block"}),
			wantBlock: true, wantReason: ReasonOutdated,
		},
		{
			name: "current chrome allowed", ua: newChrome,
			policy:     enabled(domain.BrowserPolicy{Enforcement: "block"}),
			wantReason: ReasonAllowed, wantAllowed: true,
		},
		{
			name: "explicit min version overrides default", ua: newChrome,
			policy:    enabled(domain.BrowserPolicy{Enforcement: "block", MinVersions: map[string]string{"chrome": "127"}}),
			wantBlock: true, wantReason: ReasonOutdated,
		},
		{
			name: "warn mode allows but marks violation", ua: oldChrome,
			policy:     enabled(domain.BrowserPolicy{Enforcement: "warn"}),
			wantReason: ReasonOutdated, wantAllowed: true,
		},
		{
			name: "api client is exempt by default", ua: curlUA,
			policy:     enabled(domain.BrowserPolicy{Enforcement: "block", BlockUnknown: true}),
			wantReason: ReasonExempt, wantAllowed: true,
		},
		{
			name: "custom exemption", ua: "MyCorpUpdater/2.0",
			policy:     enabled(domain.BrowserPolicy{Enforcement: "block", BlockUnknown: true, ExemptUserAgents: []string{"MyCorpUpdater/"}}),
			wantReason: ReasonExempt, wantAllowed: true,
		},
		{
			name: "unknown blocked when configured", ua: "SomeWeirdAgent/1.0",
			policy:    enabled(domain.BrowserPolicy{Enforcement: "block", BlockUnknown: true}),
			wantBlock: true, wantReason: ReasonUnknownBrowser,
		},
		{
			name: "bot blocked", ua: botUA,
			policy:    enabled(domain.BrowserPolicy{Enforcement: "block", BlockBots: true}),
			wantBlock: true, wantReason: ReasonBot,
		},
		{
			name: "bot allowed when not blocking bots", ua: botUA,
			policy:     enabled(domain.BrowserPolicy{Enforcement: "block"}),
			wantReason: ReasonAllowed, wantAllowed: true,
		},
		{
			name: "old safari blocks", ua: oldSafari,
			policy:    enabled(domain.BrowserPolicy{Enforcement: "block"}),
			wantBlock: true, wantReason: ReasonOutdated,
		},
		{
			name:      "safari minor version below baseline blocks",
			ua:        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
			policy:    enabled(domain.BrowserPolicy{Enforcement: "block"}),
			wantBlock: true, wantReason: ReasonOutdated,
		},
		{
			name:       "safari at baseline allowed",
			ua:         "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
			policy:     enabled(domain.BrowserPolicy{Enforcement: "block"}),
			wantReason: ReasonAllowed, wantAllowed: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Evaluate(tt.ua, tt.policy)
			if got.Blocked() != tt.wantBlock {
				t.Errorf("Blocked() = %v, want %v (reason=%s)", got.Blocked(), tt.wantBlock, got.Reason)
			}
			if got.Reason != tt.wantReason {
				t.Errorf("Reason = %q, want %q", got.Reason, tt.wantReason)
			}
			if got.Allowed != tt.wantAllowed {
				t.Errorf("Allowed = %v, want %v", got.Allowed, tt.wantAllowed)
			}
		})
	}
}

func TestEvaluate_RequiredVersion(t *testing.T) {
	got := Evaluate(oldChrome, &domain.BrowserPolicy{
		Enabled:     true,
		Enforcement: "block",
		MinVersions: map[string]string{"chrome": "120"},
	})
	if got.Required != "120" {
		t.Fatalf("Required = %q, want 120", got.Required)
	}
}
