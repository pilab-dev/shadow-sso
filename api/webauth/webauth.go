package webauth

import (
	"embed"
	"html/template"
	"io/fs"

	"github.com/gin-gonic/gin"
	"github.com/pilab-dev/shadow-sso/domain"
	"github.com/pilab-dev/shadow-sso/internal/authflow"
	"github.com/pilab-dev/shadow-sso/services"
)

//go:embed templates/*.html
var templatesFS embed.FS

// WebAuth holds all dependencies for the server-side web authentication UI.
// Methods for handling login, consent, and social flows will be added in subsequent todos.
type WebAuth struct {
	userRepo           domain.UserRepository
	passwordHasher     domain.PasswordHasher
	flowStore          domain.FlowStore
	userSessionStore   domain.UserSessionStore
	idpRepo            domain.IdPRepository
	federationService  services.FederationService
	oauthService       services.OAuthService
	tokenService       services.TokenService
	clientService      services.ClientService
	config             *Config
	ssoCookieSecret    string
	rateLimiter        *RateLimiter
	runner             *authflow.Runner
}

// Options configures the WebAuth instance with all required dependencies.
type Options struct {
	UserRepo           domain.UserRepository
	PasswordHasher     domain.PasswordHasher
	FlowStore          domain.FlowStore
	UserSessionStore   domain.UserSessionStore
	IdPRepository      domain.IdPRepository
	FederationService  services.FederationService
	OAuthService       services.OAuthService
	TokenService       services.TokenService
	ClientService      services.ClientService
	Config             *Config
	SSOCookieSecret    string
	AuthFlowRepo       domain.AuthenticationFlowRepository
}

// New creates a new WebAuth instance with the provided dependencies.
// If config is nil, DefaultConfig() is used.
func New(opts *Options) *WebAuth {
	cfg := opts.Config
	if cfg == nil {
		cfg = DefaultConfig()
	}

	return &WebAuth{
		userRepo:          opts.UserRepo,
		passwordHasher:    opts.PasswordHasher,
		flowStore:         opts.FlowStore,
		userSessionStore:  opts.UserSessionStore,
		idpRepo:           opts.IdPRepository,
		federationService: opts.FederationService,
		oauthService:      opts.OAuthService,
		tokenService:      opts.TokenService,
		clientService:     opts.ClientService,
		config:            cfg,
		ssoCookieSecret:   opts.SSOCookieSecret,
		rateLimiter:       NewRateLimiter(cfg.RateLimitMaxAttempts, cfg.RateLimitLockoutDuration),
		runner:            authflow.NewRunner(opts.AuthFlowRepo, opts.PasswordHasher),
	}
}

// LoadTemplates parses the embedded HTML templates and registers them with
// the gin engine so that c.HTML() calls resolve correctly.
func LoadTemplates(router *gin.Engine) error {
	subFS, err := fs.Sub(templatesFS, "templates")
	if err != nil {
		return err
	}
	tmpl := template.New("")
	if _, err := tmpl.ParseFS(subFS, "*.html"); err != nil {
		return err
	}
	router.SetHTMLTemplate(tmpl)
	return nil
}
