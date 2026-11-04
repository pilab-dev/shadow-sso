// Package browserpolicy evaluates the enterprise browser-baseline policy.
//
// The policy is about interactive browsers only. API clients (curl, ssoctl,
// SDKs, health probes) are exempt by default; otherwise enabling the policy
// would break every machine integration at once.
package browserpolicy

import (
	"context"
	"fmt"
	"html"
	"net/http"
	"strings"
	"sync"
	"time"

	"connectrpc.com/connect"
	"github.com/gin-gonic/gin"
	"github.com/pilab-dev/shadow-sso/domain"
	"github.com/pilab-dev/shadow-sso/internal/audit"
	"github.com/pilab-dev/shadow-sso/internal/browserinfo"
	"github.com/pilab-dev/shadow-sso/internal/reqinfo"
)

// Reasons returned by Evaluate.
const (
	ReasonAllowed        = "allowed"
	ReasonExempt         = "exempt"
	ReasonDisabled       = "disabled"
	ReasonUnknownBrowser = "unknown_browser"
	ReasonBot            = "bot"
	ReasonOutdated       = "outdated_browser"
)

// DefaultMinVersions is the built-in baseline. Administrators can override any
// entry; browsers not listed here are not version-checked unless the policy
// adds them.
func DefaultMinVersions() map[string]string {
	return map[string]string{
		"chrome":  "120",
		"edge":    "120",
		"firefox": "121",
		"safari":  "17.2",
		"opera":   "106",
		"samsung": "23",
	}
}

// DefaultExemptUserAgents are non-browser clients that must keep working when
// BlockUnknown is enabled. Matching is a case-insensitive substring.
func DefaultExemptUserAgents() []string {
	return []string{
		"ssoctl/",
		"curl/",
		"wget/",
		"go-http-client/",
		"python-requests/",
		"okhttp/",
		"postmanruntime/",
		"grpc-go/",
		"connect-go/",
		"kube-probe/",
		"elb-healthchecker/",
	}
}

// Decision is the result of evaluating one User-Agent.
type Decision struct {
	Allowed     bool
	Violation   bool // policy was violated, regardless of enforcement mode
	Reason      string
	Enforcement string
	Info        browserinfo.Info
	Required    string
}

// Blocked reports whether the request must be rejected.
func (d Decision) Blocked() bool {
	return d.Violation && d.Enforcement != domain.BrowserPolicyEnforcementWarn
}

// Evaluate applies the policy to a User-Agent string.
func Evaluate(ua string, policy *domain.BrowserPolicy) Decision {
	info := browserinfo.Parse(ua)
	d := Decision{Allowed: true, Reason: ReasonAllowed, Info: info}

	if policy == nil || !policy.Enabled {
		d.Reason = ReasonDisabled
		return d
	}

	d.Enforcement = policy.Enforcement
	if d.Enforcement == "" {
		d.Enforcement = domain.BrowserPolicyEnforcementBlock
	}

	if isExempt(ua, policy.ExemptUserAgents) {
		d.Reason = ReasonExempt
		return d
	}

	if info.IsBot && policy.BlockBots {
		d.markViolation(ReasonBot, "")
		return d
	}

	if !info.IsKnownBrowser() {
		if policy.BlockUnknown {
			d.markViolation(ReasonUnknownBrowser, "")
		}
		return d
	}

	required := policy.MinVersions[info.Browser]
	if required == "" {
		required = DefaultMinVersions()[info.Browser]
	}
	if required != "" && compareVersions(info.Version, required) < 0 {
		d.markViolation(ReasonOutdated, required)
	}
	return d
}

// markViolation records a policy violation. In warn mode the request is still
// allowed, but the decision is flagged so the caller can audit it.
func (d *Decision) markViolation(reason, required string) {
	d.Violation = true
	d.Reason = reason
	d.Required = required
	d.Allowed = d.Enforcement == domain.BrowserPolicyEnforcementWarn
}

func isExempt(ua string, configured []string) bool {
	lower := strings.ToLower(ua)
	for _, s := range append(DefaultExemptUserAgents(), configured...) {
		s = strings.ToLower(strings.TrimSpace(s))
		if s != "" && strings.Contains(lower, s) {
			return true
		}
	}
	return false
}

// compareVersions compares dotted numeric versions component by component.
// Missing components are treated as zero, so "17.1" < "17.2" and "120" ==
// "120.0". Non-numeric suffixes are ignored.
func compareVersions(a, b string) int {
	as := versionParts(a)
	bs := versionParts(b)
	n := len(as)
	if len(bs) > n {
		n = len(bs)
	}
	for i := 0; i < n; i++ {
		var av, bv int
		if i < len(as) {
			av = as[i]
		}
		if i < len(bs) {
			bv = bs[i]
		}
		if av < bv {
			return -1
		}
		if av > bv {
			return 1
		}
	}
	return 0
}

func versionParts(v string) []int {
	parts := strings.Split(strings.TrimSpace(v), ".")
	out := make([]int, 0, len(parts))
	for _, p := range parts {
		n := 0
		for _, r := range p {
			if r < '0' || r > '9' {
				break
			}
			n = n*10 + int(r-'0')
		}
		out = append(out, n)
	}
	return out
}

// Provider loads and caches the realm browser policy.
type Provider struct {
	repo domain.RealmSettingsRepository
	ttl  time.Duration

	mu      sync.Mutex
	cached  *domain.BrowserPolicy
	loaded  bool
	expires time.Time
}

// NewProvider returns a provider backed by realm settings. A nil repository
// yields a disabled policy, which is the safe default for tests and for
// deployments that do not configure realm settings.
func NewProvider(repo domain.RealmSettingsRepository) *Provider {
	return &Provider{repo: repo, ttl: 10 * time.Second}
}

// Policy returns the current policy, loading it from the repository at most once
// per TTL.
func (p *Provider) Policy(ctx context.Context) *domain.BrowserPolicy {
	if p == nil || p.repo == nil {
		return nil
	}
	p.mu.Lock()
	if p.loaded && time.Now().Before(p.expires) {
		policy := p.cached
		p.mu.Unlock()
		return policy
	}
	p.mu.Unlock()

	settings, err := p.repo.GetRealmSettings(ctx)
	if err != nil || settings == nil {
		return nil
	}
	p.mu.Lock()
	p.cached = settings.BrowserPolicy
	p.loaded = true
	p.expires = time.Now().Add(p.ttl)
	policy := p.cached
	p.mu.Unlock()
	return policy
}

// Invalidate drops the cached policy after an update.
func (p *Provider) Invalidate() {
	p.mu.Lock()
	p.cached = nil
	p.loaded = false
	p.expires = time.Time{}
	p.mu.Unlock()
}

// Check evaluates a User-Agent against the current policy.
func (p *Provider) Check(ctx context.Context, ua string) Decision {
	return Evaluate(ua, p.Policy(ctx))
}

// CheckConnect enforces the policy for a ConnectRPC method. It returns a
// FailedPrecondition error when the browser must be blocked.
func (p *Provider) CheckConnect(ctx context.Context, header http.Header) error {
	info := reqinfo.FromContext(ctx)
	if info.UserAgent == "" {
		info = reqinfo.FromHeaders(ctx, header)
	}
	d := p.Check(ctx, info.UserAgent)
	if !d.Blocked() {
		if d.Violation {
			auditDecision(ctx, info, d, true)
		}
		return nil
	}
	auditDecision(ctx, info, d, false)
	return connect.NewError(connect.CodeFailedPrecondition,
		fmt.Errorf("browser %s %s is below the required version %s; update your browser to continue",
			d.Info.Browser, d.Info.Version, d.Required))
}

// Middleware rejects interactive HTTP requests from non-compliant browsers.
// Only the supplied path prefixes are checked; API endpoints stay untouched.
func (p *Provider) Middleware(prefixes ...string) gin.HandlerFunc {
	if len(prefixes) == 0 {
		prefixes = []string{"/login", "/oauth2/authorize", "/oauth2/silent-authorize", "/mfa", "/consent"}
	}
	return func(c *gin.Context) {
		path := c.Request.URL.Path
		matched := false
		for _, prefix := range prefixes {
			if strings.HasPrefix(path, prefix) {
				matched = true
				break
			}
		}
		if !matched {
			c.Next()
			return
		}

		info := reqinfo.FromHTTP(c.Request)
		d := p.Check(c.Request.Context(), info.UserAgent)
		if !d.Blocked() {
			if d.Violation && c.Request.Method != http.MethodGet && c.Request.Method != http.MethodHead {
				auditDecision(c.Request.Context(), info, d, true)
			}
			c.Next()
			return
		}
		auditDecision(c.Request.Context(), info, d, false)

		msg := "Your browser is not supported."
		if d.Reason == ReasonOutdated {
			msg = fmt.Sprintf("This browser (%s %s) is out of date. Please update to version %s or newer.",
				d.Info.Browser, d.Info.Version, d.Required)
		} else if d.Reason == ReasonBot {
			msg = "Automated browsers are not allowed to sign in."
		} else if d.Reason == ReasonUnknownBrowser {
			msg = "This browser could not be identified. Please use a current browser."
		}
		if strings.HasPrefix(path, "/oauth2/") || strings.Contains(c.GetHeader("Accept"), "application/json") {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error":             "browser_not_supported",
				"error_description": msg,
				"reason":            d.Reason,
			})
			return
		}
		c.Data(http.StatusForbidden, "text/html; charset=utf-8", []byte(browserBlockPage(msg)))
		c.Abort()
	}
}

func browserBlockPage(message string) string {
	return `<!doctype html><html><head><meta charset="utf-8"><title>Browser not supported</title>` +
		`<meta name="viewport" content="width=device-width,initial-scale=1">` +
		`<style>body{font-family:system-ui,sans-serif;max-width:40rem;margin:4rem auto;padding:0 1rem;line-height:1.5}h1{font-size:1.5rem}</style>` +
		`</head><body><h1>Browser not supported</h1><p>` + html.EscapeString(message) +
		`</p><p>Contact your administrator if you believe this is a mistake.</p></body></html>`
}

func auditDecision(ctx context.Context, info reqinfo.Info, d Decision, allowed bool) {
	action := "BrowserBlocked"
	if allowed {
		action = "BrowserPolicyWarn"
	}
	details := fmt.Sprintf("browser=%s version=%s required=%s reason=%s enforcement=%s %s",
		d.Info.Browser, d.Info.Version, d.Required, d.Reason, d.Enforcement, info.Details())
	audit.Log("BrowserPolicy", action, "", "", details, allowed, nil)
}
