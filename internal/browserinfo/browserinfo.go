// Package browserinfo parses User-Agent strings just far enough to make
// security decisions: browser family, version, operating system and device
// class. It has no external dependencies and never returns an error — an
// unparseable UA is reported as unknown, which the policy layer can choose to
// allow or block.
package browserinfo

import (
	"regexp"
	"strconv"
	"strings"
)

// Info is the parsed view of a User-Agent header.
type Info struct {
	// Browser is a stable lower-case family name: chrome, edge, firefox,
	// safari, opera, samsung, ie, curl, go-http-client, ...
	Browser string
	// Version is the full version string (e.g. "120.0.6099.109"), empty when
	// the UA did not carry one.
	Version string
	// Major is the numeric first component of Version, or 0.
	Major int
	// OS is a stable lower-case operating system name: windows, macos, linux,
	// ios, android, chromeos, ...
	OS string
	// DeviceType is desktop, mobile, tablet, bot or unknown.
	DeviceType string
	// IsBot marks crawlers, link previewers and other automated agents.
	IsBot bool
	// IsAutomation marks headless browsers and known HTTP client libraries.
	IsAutomation bool
	Raw          string
}

var (
	versionRe = regexp.MustCompile(`([0-9]+(?:\.[0-9A-Za-z]+)*)`)

	// Order matters: Edge and Opera also contain "Chrome/", Chrome iOS contains
	// "Safari/", and Samsung contains both.
	browserPatterns = []struct {
		name string
		re   *regexp.Regexp
	}{
		{"edge", regexp.MustCompile(`(?:Edg|Edge|EdgiOS|EdgA)/([0-9][0-9A-Za-z.]*)`)},
		{"opera", regexp.MustCompile(`(?:OPR|Opera)/([0-9][0-9A-Za-z.]*)`)},
		{"samsung", regexp.MustCompile(`SamsungBrowser/([0-9][0-9A-Za-z.]*)`)},
		{"chrome", regexp.MustCompile(`CriOS/([0-9][0-9A-Za-z.]*)`)},
		{"chrome", regexp.MustCompile(`Chrome/([0-9][0-9A-Za-z.]*)`)},
		{"firefox", regexp.MustCompile(`FxiOS/([0-9][0-9A-Za-z.]*)`)},
		{"firefox", regexp.MustCompile(`Firefox/([0-9][0-9A-Za-z.]*)`)},
		{"safari", regexp.MustCompile(`Version/([0-9][0-9A-Za-z.]*).*Safari/`)},
		{"ie", regexp.MustCompile(`MSIE ([0-9][0-9A-Za-z.]*)`)},
		{"ie", regexp.MustCompile(`Trident/.*rv:([0-9][0-9A-Za-z.]*)`)},
	}

	apiClients = []struct {
		name string
		re   *regexp.Regexp
	}{
		{"ssoctl", regexp.MustCompile(`(?i)^ssoctl/([0-9][0-9A-Za-z.]*)`)},
		{"curl", regexp.MustCompile(`(?i)^curl/([0-9][0-9A-Za-z.]*)`)},
		{"wget", regexp.MustCompile(`(?i)^Wget/([0-9][0-9A-Za-z.]*)`)},
		{"go-http-client", regexp.MustCompile(`(?i)^Go-http-client/([0-9][0-9A-Za-z.]*)`)},
		{"python-requests", regexp.MustCompile(`(?i)^python-requests/([0-9][0-9A-Za-z.]*)`)},
		{"okhttp", regexp.MustCompile(`(?i)^okhttp/([0-9][0-9A-Za-z.]*)`)},
		{"postman", regexp.MustCompile(`(?i)^PostmanRuntime/([0-9][0-9A-Za-z.]*)`)},
		{"grpc-go", regexp.MustCompile(`(?i)^grpc-go/([0-9][0-9A-Za-z.]*)`)},
		{"connect-go", regexp.MustCompile(`(?i)^connect-go/([0-9][0-9A-Za-z.]*)`)},
	}

	botMarkers = []string{
		"bot", "crawler", "spider", "slurp", "bingpreview", "facebookexternalhit",
		"headlesschrome", "phantomjs", "selenium", "puppeteer", "playwright",
	}
)

// Parse inspects a User-Agent string. The result is always non-nil; unknown
// agents yield Browser="" and DeviceType="unknown".
func Parse(ua string) Info {
	raw := strings.TrimSpace(ua)
	info := Info{Raw: raw, DeviceType: "unknown", OS: osFamily(raw)}
	lower := strings.ToLower(raw)

	for _, marker := range botMarkers {
		if strings.Contains(lower, marker) {
			info.IsBot = true
			info.DeviceType = "bot"
			break
		}
	}

	for _, c := range apiClients {
		if m := c.re.FindStringSubmatch(raw); len(m) == 2 {
			info.Browser = c.name
			info.Version = m[1]
			info.Major = majorOf(m[1])
			info.IsAutomation = true
			info.DeviceType = "desktop"
			return info
		}
	}

	for _, p := range browserPatterns {
		if m := p.re.FindStringSubmatch(raw); len(m) == 2 {
			info.Browser = p.name
			info.Version = m[1]
			info.Major = majorOf(m[1])
			break
		}
	}

	if info.DeviceType == "unknown" {
		info.DeviceType = deviceType(raw, info.OS)
	}
	return info
}

// IsKnownBrowser reports whether the agent is a real browser family we can
// version-check.
func (i Info) IsKnownBrowser() bool {
	switch i.Browser {
	case "chrome", "edge", "firefox", "safari", "opera", "samsung", "ie":
		return true
	default:
		return false
	}
}

func majorOf(version string) int {
	if version == "" {
		return 0
	}
	if m := versionRe.FindStringSubmatch(version); len(m) == 2 {
		version = m[1]
	}
	first := strings.SplitN(version, ".", 2)[0]
	n, _ := strconv.Atoi(first)
	return n
}

func osFamily(ua string) string {
	lower := strings.ToLower(ua)
	switch {
	case strings.Contains(lower, "windows"):
		return "windows"
	case strings.Contains(lower, "cros"):
		return "chromeos"
	case strings.Contains(lower, "iphone"), strings.Contains(lower, "ipad"), strings.Contains(lower, "ipod"):
		return "ios"
	case strings.Contains(lower, "android"):
		return "android"
	case strings.Contains(lower, "mac os x"), strings.Contains(lower, "macintosh"):
		return "macos"
	case strings.Contains(lower, "linux"):
		return "linux"
	default:
		return ""
	}
}

func deviceType(ua, os string) string {
	lower := strings.ToLower(ua)
	switch os {
	case "ios":
		if strings.Contains(lower, "ipad") {
			return "tablet"
		}
		return "mobile"
	case "android":
		if strings.Contains(lower, "mobile") {
			return "mobile"
		}
		return "tablet"
	case "windows", "macos", "linux", "chromeos":
		return "desktop"
	}
	if strings.Contains(lower, "mobile") {
		return "mobile"
	}
	return "unknown"
}
