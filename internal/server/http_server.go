package server

import (
	"context"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/pilab-dev/shadow-sso/config" // Assuming this is the correct path
	"github.com/pilab-dev/shadow-sso/log"    // Assuming this is the correct path
	"go.opentelemetry.io/contrib/instrumentation/github.com/gin-gonic/gin/otelgin"

	ginapi "github.com/pilab-dev/shadow-sso/api/gin" // Alias for clarity
	// Placeholder for other dependencies like services if OAuth2API needs them directly
	// For now, assuming NewOAuth2API is self-contained or takes what it needs from a higher level setup
)

// NewHTTPServer creates and configures a new Gin HTTP server.
func NewHTTPServer(cfg *config.ServerConfig, appLogger log.Logger, oauthAPI *ginapi.OAuth2API) *http.Server {
	// Set Gin mode based on configuration (e.g., debug, release, test)
	// For now, defaulting to debug mode. This could come from cfg.GinMode or similar.
	gin.SetMode(gin.DebugMode)

	router := gin.New()

	// Add Gin's built-in recovery middleware
	router.Use(gin.Recovery())

	// Add custom logging middleware using our logger interface
	router.Use(func(c *gin.Context) {
		start := time.Now()
		c.Next() // Process request

		latency := time.Since(start)
		fields := map[string]interface{}{
			"method":     c.Request.Method,
			"path":       c.Request.URL.Path,
			"status":     c.Writer.Status(),
			"latency":    latency.String(),
			"ip":         c.ClientIP(),
			"user_agent": c.Request.UserAgent(),
		}
		// Add error to log fields if one occurred
		if len(c.Errors) > 0 {
			// Log only the first error for brevity, or concatenate them
			appLogger.Error(c.Request.Context(), c.Errors.String(), c.Errors.Last().Err, fields)
		} else {
			appLogger.Info(c.Request.Context(), "HTTP Request", fields)
		}
	})

	// Add OpenTelemetry Gin Middleware
	// The service name for tracing will be taken from the config.
	router.Use(otelgin.Middleware(cfg.OtelServiceName))

	// Register API routes
	// Assuming OAuth2API is already initialized with its dependencies (OAuthService, etc.)
	// If NewOAuth2API needs more direct dependencies here (e.g., specific services),
	// they would need to be passed into NewHTTPServer or created here.
	// For now, let's assume oauthAPI is pre-configured.
	if oauthAPI == nil {
		// This indicates a setup problem, as oauthAPI is expected.
		// In a real app, this might panic or log a fatal error.
		// For now, log and continue, routes won't be registered.
		appLogger.Error(context.Background(), "OAuth2API not provided to NewHTTPServer, API routes will not be registered.", nil)
	} else {
		oauthAPI.RegisterRoutes(router) // Registering routes from api/gin/handlers.go
	}

	// TODO: Add other route groups or handlers here if necessary
	// e.g., router.GET("/health", func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"status": "ok"}) })

	srv := &http.Server{
		Addr:    ":" + cfg.HTTPPort,
		Handler: router,
		// Example: Set some timeouts for robustness
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	return srv
}
