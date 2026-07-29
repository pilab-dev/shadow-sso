package graphql_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/pilab-dev/shadow-sso/domain"
	"github.com/pilab-dev/shadow-sso/graphql"
)

// MockTokenService implements graphql.TokenService for testing
type MockTokenService struct {
	ValidateAccessTokenFunc func(ctx context.Context, tokenValue string) (*domain.Token, error)
}

func (m *MockTokenService) ValidateAccessToken(ctx context.Context, tokenValue string) (*domain.Token, error) {
	if m.ValidateAccessTokenFunc != nil {
		return m.ValidateAccessTokenFunc(ctx, tokenValue)
	}
	return nil, fmt.Errorf("not implemented")
}

// testHandler is a simple handler that returns 200 and optionally includes token info from context
func testHandler(includeTokenInfo bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if includeTokenInfo {
			tokenInfo, ok := domain.GetAuthenticatedTokenFromContext(r.Context())
			if ok {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("user_id:" + tokenInfo.UserID))
				return
			}
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	}
}

func TestGraphQLAuth(t *testing.T) {
	validToken := "valid-test-token-123"

	t.Run("valid token passes auth", func(t *testing.T) {
		mockService := &MockTokenService{
			ValidateAccessTokenFunc: func(ctx context.Context, tokenValue string) (*domain.Token, error) {
				if tokenValue != validToken {
					return nil, fmt.Errorf("invalid token")
				}
				return &domain.Token{
					ID:        "token-1",
					TokenType: domain.TokenTypeAccessToken,
					UserID:    "user-42",
					ClientID:  "client-1",
					Scope:     "openid",
					ExpiresAt: time.Now().Add(1 * time.Hour),
					CreatedAt: time.Now(),
					Roles:     []string{"admin"},
				}, nil
			},
		}

		handler := graphql.AuthMiddleware(mockService, "", testHandler(true))
		req := httptest.NewRequest(http.MethodGet, "/graphql", nil)
		req.Header.Set("Authorization", "Bearer "+validToken)
		rr := httptest.NewRecorder()

		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("expected status 200, got %d", rr.Code)
		}
		if rr.Body.String() != "user_id:user-42" {
			t.Errorf("expected user_id:user-2, got %s", rr.Body.String())
		}
	})

	t.Run("missing token returns 401", func(t *testing.T) {
		mockService := &MockTokenService{}
		handler := graphql.AuthMiddleware(mockService, "", testHandler(false))
		req := httptest.NewRequest(http.MethodGet, "/graphql", nil)
		rr := httptest.NewRecorder()

		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusUnauthorized {
			t.Errorf("expected status 401, got %d", rr.Code)
		}
	})

	t.Run("invalid token returns 401", func(t *testing.T) {
		mockService := &MockTokenService{
			ValidateAccessTokenFunc: func(ctx context.Context, tokenValue string) (*domain.Token, error) {
				return nil, fmt.Errorf("token validation failed")
			},
		}

		handler := graphql.AuthMiddleware(mockService, "", testHandler(false))
		req := httptest.NewRequest(http.MethodGet, "/graphql", nil)
		req.Header.Set("Authorization", "Bearer invalid-token")
		rr := httptest.NewRecorder()

		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusUnauthorized {
			t.Errorf("expected status 401, got %d", rr.Code)
		}
	})

	t.Run("expired token returns 401", func(t *testing.T) {
		mockService := &MockTokenService{
			ValidateAccessTokenFunc: func(ctx context.Context, tokenValue string) (*domain.Token, error) {
				return &domain.Token{
					ID:        "token-2",
					TokenType: domain.TokenTypeAccessToken,
					UserID:    "user-42",
					ExpiresAt: time.Now().Add(-1 * time.Hour), // expired
					CreatedAt: time.Now().Add(-2 * time.Hour),
					IsRevoked: false,
				}, nil
			},
		}

		handler := graphql.AuthMiddleware(mockService, "", testHandler(false))
		req := httptest.NewRequest(http.MethodGet, "/graphql", nil)
		req.Header.Set("Authorization", "Bearer "+validToken)
		rr := httptest.NewRecorder()

		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusUnauthorized {
			t.Errorf("expected status 401, got %d", rr.Code)
		}
	})

	t.Run("revoked token returns 401", func(t *testing.T) {
		mockService := &MockTokenService{
			ValidateAccessTokenFunc: func(ctx context.Context, tokenValue string) (*domain.Token, error) {
				return &domain.Token{
					ID:        "token-3",
					TokenType: domain.TokenTypeAccessToken,
					UserID:    "user-42",
					ExpiresAt: time.Now().Add(1 * time.Hour),
					CreatedAt: time.Now(),
					IsRevoked: true,
				}, nil
			},
		}

		handler := graphql.AuthMiddleware(mockService, "", testHandler(false))
		req := httptest.NewRequest(http.MethodGet, "/graphql", nil)
		req.Header.Set("Authorization", "Bearer "+validToken)
		rr := httptest.NewRecorder()

		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusUnauthorized {
			t.Errorf("expected status 401, got %d", rr.Code)
		}
	})

	t.Run("sandbox endpoint exempt from auth", func(t *testing.T) {
		mockService := &MockTokenService{}
		handler := graphql.AuthMiddleware(mockService, "", testHandler(false))
		req := httptest.NewRequest(http.MethodGet, "/sandbox", nil)
		rr := httptest.NewRecorder()

		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("expected status 200 for sandbox, got %d", rr.Code)
		}
	})

	t.Run("malformed bearer header returns 401", func(t *testing.T) {
		mockService := &MockTokenService{}
		handler := graphql.AuthMiddleware(mockService, "", testHandler(false))
		req := httptest.NewRequest(http.MethodGet, "/graphql", nil)
		req.Header.Set("Authorization", "Basic abc123")
		rr := httptest.NewRecorder()

		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusUnauthorized {
			t.Errorf("expected status 401, got %d", rr.Code)
		}
	})

	t.Run("empty bearer token returns 401", func(t *testing.T) {
		mockService := &MockTokenService{}
		handler := graphql.AuthMiddleware(mockService, "", testHandler(false))
		req := httptest.NewRequest(http.MethodGet, "/graphql", nil)
		req.Header.Set("Authorization", "Bearer ")
		rr := httptest.NewRecorder()

		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusUnauthorized {
			t.Errorf("expected status 401, got %d", rr.Code)
		}
	})
}
