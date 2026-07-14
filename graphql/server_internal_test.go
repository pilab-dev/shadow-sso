package graphql

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCheckOrigin(t *testing.T) {
	tests := []struct {
		name   string
		cfg    GraphQLConfig
		origin string
		want   bool
	}{
		{
			name:   "empty origin allowed",
			cfg:    GraphQLConfig{AllowedOrigins: []string{"https://app.example.com"}},
			origin: "",
			want:   true,
		},
		{
			name:   "dev mode allows any origin",
			cfg:    GraphQLConfig{IsDevelopment: true},
			origin: "https://evil.example.com",
			want:   true,
		},
		{
			name:   "exact match allowed",
			cfg:    GraphQLConfig{AllowedOrigins: []string{"https://app.example.com"}},
			origin: "https://app.example.com",
			want:   true,
		},
		{
			name:   "no match rejected",
			cfg:    GraphQLConfig{AllowedOrigins: []string{"https://app.example.com"}},
			origin: "https://evil.example.com",
			want:   false,
		},
		{
			name:   "trailing slash normalized",
			cfg:    GraphQLConfig{AllowedOrigins: []string{"https://app.example.com"}},
			origin: "https://app.example.com/",
			want:   true,
		},
		{
			name:   "multiple allowed origins",
			cfg:    GraphQLConfig{AllowedOrigins: []string{"https://a.example.com", "https://b.example.com"}},
			origin: "https://b.example.com",
			want:   true,
		},
		{
			name:   "empty allowed list rejects non-empty origin",
			cfg:    GraphQLConfig{AllowedOrigins: []string{}},
			origin: "https://anything.example.com",
			want:   false,
		},
		{
			name:   "nil allowed list rejects non-empty origin",
			cfg:    GraphQLConfig{},
			origin: "https://anything.example.com",
			want:   false,
		},
		{
			name:   "port mismatch rejected",
			cfg:    GraphQLConfig{AllowedOrigins: []string{"https://app.example.com:8080"}},
			origin: "https://app.example.com:9090",
			want:   false,
		},
		{
			name:   "scheme mismatch rejected",
			cfg:    GraphQLConfig{AllowedOrigins: []string{"https://app.example.com"}},
			origin: "http://app.example.com",
			want:   false,
		},
		{
			name:   "invalid origin rejected",
			cfg:    GraphQLConfig{AllowedOrigins: []string{"https://app.example.com"}},
			origin: "://bad",
			want:   false,
		},
		{
			name:   "empty string in allowed list ignored",
			cfg:    GraphQLConfig{AllowedOrigins: []string{"", "https://app.example.com"}},
			origin: "https://app.example.com",
			want:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			checker := checkOrigin(tt.cfg)
			req := httptest.NewRequest(http.MethodGet, "/graphql", nil)
			if tt.origin != "" {
				req.Header.Set("Origin", tt.origin)
			}
			got := checker(req)
			if got != tt.want {
				t.Errorf("checkOrigin with origin %q = %v, want %v", tt.origin, got, tt.want)
			}
		})
	}
}
