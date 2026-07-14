package graphql

import (
	"html/template"
	"net/http"
	"net/url"
	"strings"

	"github.com/99designs/gqlgen/graphql/handler"
	"github.com/99designs/gqlgen/graphql/handler/extension"
	"github.com/99designs/gqlgen/graphql/handler/lru"
	"github.com/99designs/gqlgen/graphql/handler/transport"
	"github.com/gorilla/websocket"
)

var sandboxHTML = template.Must(template.New("sandbox").Parse(`<!DOCTYPE html>
<html>
<head>
  <title>Shadow SSO - GraphQL Explorer</title>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; height: 100vh; }
    #sandbox { width: 100%; height: 100%; }
  </style>
  <link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='.9em' font-size='90'>🔐</text></svg>">
</head>
<body>
  <div id="sandbox">
    <div style="display: flex; align-items: center; justify-content: center; height: 100vh; background: #1a1a2e; color: #eee;">
      <div style="text-align: center;">
        <div style="font-size: 48px; margin-bottom: 16px;">🔐</div>
        <div style="font-size: 24px; margin-bottom: 8px;">Shadow SSO GraphQL</div>
        <div style="color: #888;">Loading Explorer...</div>
      </div>
    </div>
  </div>
  <script src="https://embeddable-sandbox.cdn.apollographql.com/_latest/embeddable-sandbox.umd.production.min.js"></script>
  <script>
    new window.ApolloSandbox({
      target: '#sandbox',
      initialEndpoint: '{{.Endpoint}}',
      includeCookies: true
    });
  </script>
</body>
</html>`))

// GraphQLConfig holds configuration for the GraphQL server.
type GraphQLConfig struct {
	// AllowedOrigins is a list of allowed origin URLs for WebSocket connections.
	// Empty strings and entries matching the full origin are allowed.
	// Use []string{"*"} or set IsDevelopment to true to allow all origins.
	AllowedOrigins []string

	// IsDevelopment when true allows all origins (disables origin checking).
	IsDevelopment bool
}

// checkOrigin returns a WebSocket origin checker that validates the request's
// Origin header against the configured allowed origins.
//
// Rules:
//   - Empty Origin header is always allowed (same-origin requests).
//   - If IsDevelopment is true, all origins are allowed.
//   - Otherwise, the Origin must exactly match one of AllowedOrigins.
func checkOrigin(cfg GraphQLConfig) func(r *http.Request) bool {
	if cfg.IsDevelopment {
		return func(_ *http.Request) bool { return true }
	}

	allowed := make(map[string]struct{}, len(cfg.AllowedOrigins))
	for _, o := range cfg.AllowedOrigins {
		if o != "" {
			allowed[o] = struct{}{}
		}
	}

	return func(r *http.Request) bool {
		origin := r.Header.Get("Origin")
		if origin == "" {
			return true
		}
		// Parse to normalize scheme://host[:port]
		parsed, err := url.Parse(origin)
		if err != nil {
			return false
		}
		normalized := strings.TrimRight(parsed.Scheme+"://"+parsed.Host, "/")
		_, ok := allowed[normalized]
		return ok
	}
}

// NewHandler creates a new GraphQL handler with Apollo Sandbox support.
// Pass a zero-value GraphQLConfig to get default behavior (deny all origins except empty).
func NewHandler(resolver *Resolver, endpoint string, cfg GraphQLConfig) http.Handler {
	srv := handler.New(NewExecutableSchema(Config{Resolvers: resolver}))

	// Configure transports
	srv.AddTransport(transport.Options{})
	srv.AddTransport(transport.GET{})
	srv.AddTransport(transport.POST{})
	srv.AddTransport(transport.Websocket{
		Upgrader: websocket.Upgrader{
			CheckOrigin:  checkOrigin(cfg),
			ReadBufferSize:  1024,
			WriteBufferSize: 1024,
		},
	})
	srv.AddTransport(transport.MultipartForm{})

	// Add introspection for schema explorer
	srv.Use(extension.Introspection{})
	srv.Use(extension.AutomaticPersistedQuery{
		Cache: lru.New[string](100),
	})

	return srv
}

// SandboxHandler serves the Apollo Sandbox UI
func SandboxHandler(endpoint string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sandboxHTML.Execute(w, map[string]string{
			"Endpoint": endpoint,
		})
	}
}
