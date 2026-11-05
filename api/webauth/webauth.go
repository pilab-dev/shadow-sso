package webauth

import (
	"embed"
	"html/template"
	"io/fs"
	"net/http"
	"os"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/pilab-dev/shadow-sso/domain"
	"github.com/pilab-dev/shadow-sso/internal/authflow"
	"github.com/pilab-dev/shadow-sso/internal/oidcflow"
	"github.com/pilab-dev/shadow-sso/port"
	"github.com/pilab-dev/shadow-sso/services"
)

//go:embed templates/*.html
var templatesFS embed.FS

//go:embed static
var staticFS embed.FS

// WebAuth holds all dependencies for the server-side web authentication UI.
// Methods for handling login, consent, and social flows will be added in subsequent todos.
type WebAuth struct {
	userRepo          domain.UserRepository
	passwordHasher    domain.PasswordHasher
	flowStore         domain.FlowStore
	userSessionStore  domain.UserSessionStore
	idpRepo           domain.IdPRepository
	federationService services.FederationService
	oauthService      services.OAuthService
	tokenService      services.TokenService
	clientService     services.ClientService
	config            *Config
	ssoCookieSecret   string
	rateLimiter       *RateLimiter
	runner            *authflow.Runner
	realmSettingsRepo domain.RealmSettingsRepository
	// deviceAuthRepo backs the device authorization flow verification UI.
	// It is nil-safe: consumers MUST check for nil and degrade gracefully
	// (e.g. render an error page) rather than panic when unset.
	deviceAuthRepo domain.DeviceAuthorizationRepository
	// mfaService dispatches and verifies non-TOTP MFA challenges (email OTP,
	// push) for the login flow. Nil-safe: EMAIL MFA users see an error page
	// rather than panic when unset.
	mfaService *domain.MFAService
	// emailService sends verification and password-reset mail. Nil-safe: flows that
	// need it degrade to an explicit "not available" page, never a silent success.
	emailService domain.EmailService
	// publicBaseURL (no trailing slash) is the externally reachable SSO origin used to
	// build links in emails.
	publicBaseURL string
	// sessionRepo backs the account console's device-activity page. Optional.
	sessionRepo domain.SessionRepository
	// webAuthn is the passkey relying party. Nil disables passkey UI and endpoints.
	webAuthn *webauthn.WebAuthn
}

// Options configures the WebAuth instance with all required dependencies.
type Options struct {
	UserRepo          domain.UserRepository
	PasswordHasher    domain.PasswordHasher
	FlowStore         domain.FlowStore
	UserSessionStore  domain.UserSessionStore
	IdPRepository     domain.IdPRepository
	FederationService services.FederationService
	OAuthService      services.OAuthService
	TokenService      services.TokenService
	ClientService     services.ClientService
	Config            *Config
	SSOCookieSecret   string
	AuthFlowRepo      domain.AuthenticationFlowRepository
	RealmSettingsRepo domain.RealmSettingsRepository
	// DeviceAuthRepo is optional; when nil, device-flow handlers must not panic.
	DeviceAuthRepo domain.DeviceAuthorizationRepository
	// MFAService is optional; when nil, EMAIL/PUSH MFA login attempts fail
	// gracefully with an error page instead of panicking. TOTP does not need it.
	MFAService *domain.MFAService
	// EmailService is optional; without it forgot-password and email verification are unavailable.
	EmailService domain.EmailService
	// PublicBaseURL is the SSO's public origin, e.g. https://sso.example.com (used for email links).
	PublicBaseURL string
	// SessionRepo is optional; without it the device-activity page is empty and password changes
	// cannot revoke other sessions.
	SessionRepo domain.SessionRepository
	// WebAuthn enables passkeys (see NewWebAuthn). Optional.
	WebAuthn *webauthn.WebAuthn
}

// New creates a new WebAuth instance with the provided dependencies.
// If config is nil, DefaultConfig() is used.
func New(opts *Options) *WebAuth {
	cfg := opts.Config
	if cfg == nil {
		cfg = DefaultConfig()
	}
	userSessionStore := opts.UserSessionStore
	if userSessionStore == nil {
		userSessionStore = oidcflow.NewInMemoryUserSessionStore()
	}

	return &WebAuth{
		userRepo:          opts.UserRepo,
		passwordHasher:    opts.PasswordHasher,
		flowStore:         opts.FlowStore,
		userSessionStore:  userSessionStore,
		idpRepo:           opts.IdPRepository,
		federationService: opts.FederationService,
		oauthService:      opts.OAuthService,
		tokenService:      opts.TokenService,
		clientService:     opts.ClientService,
		config:            cfg,
		ssoCookieSecret:   opts.SSOCookieSecret,
		rateLimiter:       NewRateLimiter(cfg.RateLimitMaxAttempts, cfg.RateLimitLockoutDuration),
		runner:            authflow.NewRunner(opts.AuthFlowRepo, opts.PasswordHasher),
		realmSettingsRepo: opts.RealmSettingsRepo,
		deviceAuthRepo:    opts.DeviceAuthRepo,
		mfaService:        opts.MFAService,
		emailService:      opts.EmailService,
		publicBaseURL:     strings.TrimRight(opts.PublicBaseURL, "/"),
		sessionRepo:       opts.SessionRepo,
		webAuthn:          opts.WebAuthn,
	}
}

// LoadTemplates parses the embedded HTML templates and registers them with
// the gin engine so that c.HTML() calls resolve correctly.
// LoadTemplates parses HTML templates and registers them with the gin engine.
// If loader is non-nil (e.g. an internal/templates.Loader), its filesystem is
// used so operators can override templates on disk without rebuilding.
func LoadTemplates(router *gin.Engine, loader ...port.TemplateLoader) error {
	var subFS fs.FS
	if len(loader) > 0 && loader[0] != nil {
		subFS = loader[0].FS()
		if _, err := fs.Stat(subFS, "templates"); err == nil {
			if s, err := fs.Sub(subFS, "templates"); err == nil {
				subFS = s
			}
		}
	} else if dir := os.Getenv("SHADOW_SSO_TEMPLATE_DIR"); dir != "" {
		if _, err := os.Stat(dir); err == nil {
			subFS = os.DirFS(dir)
			if _, err := fs.Stat(subFS, "templates"); err == nil {
				if s, err := fs.Sub(subFS, "templates"); err == nil {
					subFS = s
				}
			}
		} else {
			s, err := fs.Sub(templatesFS, "templates")
			if err != nil {
				return err
			}
			subFS = s
		}
	} else {
		s, err := fs.Sub(templatesFS, "templates")
		if err != nil {
			return err
		}
		subFS = s
	}
	tmpl := template.New("")
	if _, err := tmpl.ParseFS(subFS, "*.html"); err != nil {
		return err
	}
	router.SetHTMLTemplate(tmpl)
	return nil
}

// StaticHandler serves the embedded static assets (self-hosted fonts and
// supporting CSS). Mount it at /static/ so no external font or style CDN is
// required at runtime.
func StaticHandler() (gin.HandlerFunc, error) {
	subFS, err := fs.Sub(staticFS, "static")
	if err != nil {
		return nil, err
	}
	fileServer := http.StripPrefix("/static/", http.FileServer(http.FS(subFS)))
	return func(c *gin.Context) {
		if strings.HasSuffix(c.Request.URL.Path, ".woff2") {
			c.Header("Content-Type", "font/woff2")
		}
		if strings.HasSuffix(c.Request.URL.Path, ".css") {
			c.Header("Content-Type", "text/css; charset=utf-8")
		}
		c.Header("Cache-Control", "public, max-age=86400")
		fileServer.ServeHTTP(c.Writer, c.Request)
	}, nil
}
