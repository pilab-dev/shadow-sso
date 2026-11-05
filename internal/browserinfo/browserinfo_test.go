package browserinfo

import "testing"

func TestParse(t *testing.T) {
	tests := []struct {
		name      string
		ua        string
		browser   string
		major     int
		os        string
		device    string
		wantBot   bool
		wantAutom bool
	}{
		{
			name:    "chrome desktop",
			ua:      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
			browser: "chrome", major: 126, os: "windows", device: "desktop",
		},
		{
			name:    "edge desktop",
			ua:      "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 Edg/126.0.2592.87",
			browser: "edge", major: 126, os: "macos", device: "desktop",
		},
		{
			name:    "safari ipados",
			ua:      "Mozilla/5.0 (iPad; CPU OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1",
			browser: "safari", major: 17, os: "ios", device: "tablet",
		},
		{
			name:    "firefox linux",
			ua:      "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
			browser: "firefox", major: 128, os: "linux", device: "desktop",
		},
		{
			name:    "chrome android mobile",
			ua:      "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.6478.122 Mobile Safari/537.36",
			browser: "chrome", major: 126, os: "android", device: "mobile",
		},
		{
			name:    "samsung internet",
			ua:      "Mozilla/5.0 (Linux; Android 13; SM-S911B) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/23.0 Chrome/115.0.0.0 Mobile Safari/537.36",
			browser: "samsung", major: 23, os: "android", device: "mobile",
		},
		{
			name:    "googlebot",
			ua:      "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
			wantBot: true, device: "bot",
		},
		{
			name:    "ssoctl",
			ua:      "ssoctl/1.1.0 (darwin; arm64)",
			browser: "ssoctl", major: 1, device: "desktop", wantAutom: true,
		},
		{
			name:    "curl",
			ua:      "curl/8.7.1",
			browser: "curl", major: 8, device: "desktop", wantAutom: true,
		},
		{
			name:   "empty",
			ua:     "",
			device: "unknown",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Parse(tt.ua)
			if got.Browser != tt.browser {
				t.Errorf("Browser = %q, want %q", got.Browser, tt.browser)
			}
			if got.Major != tt.major {
				t.Errorf("Major = %d, want %d", got.Major, tt.major)
			}
			if got.OS != tt.os {
				t.Errorf("OS = %q, want %q", got.OS, tt.os)
			}
			if got.DeviceType != tt.device {
				t.Errorf("DeviceType = %q, want %q", got.DeviceType, tt.device)
			}
			if got.IsBot != tt.wantBot {
				t.Errorf("IsBot = %v, want %v", got.IsBot, tt.wantBot)
			}
			if got.IsAutomation != tt.wantAutom {
				t.Errorf("IsAutomation = %v, want %v", got.IsAutomation, tt.wantAutom)
			}
		})
	}
}

func TestParse_BotMarkerDoesNotOverrideBrowserFamily(t *testing.T) {
	got := Parse("Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 Chrome/126.0.0.0 Safari/537.36 HeadlessChrome/126.0.0.0")
	if !got.IsBot {
		t.Fatal("expected headless chrome to be marked as bot")
	}
	if got.Browser != "chrome" {
		t.Fatalf("Browser = %q, want chrome", got.Browser)
	}
	if got.DeviceType != "bot" {
		t.Fatalf("DeviceType = %q, want bot", got.DeviceType)
	}
}
