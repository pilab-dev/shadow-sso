package graphql

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/pilab-dev/shadow-sso/domain"
	"github.com/rs/zerolog/log"
)

// TokenService defines the interface needed for token validation.
// This mirrors the relevant method from services.TokenService.
type TokenService interface {
	ValidateAccessToken(ctx context.Context, tokenValue string) (*domain.Token, error)
}

// AuthMiddleware creates an HTTP middleware that validates JWT Bearer tokens
// or a configured bootstrap token. It extracts and validates tokens from the
// Authorization header, and enriches the context with the authenticated token info.
// If bootstrapToken is non-empty, it is accepted as a valid admin token.
// The /sandbox endpoint is exempt from authentication.
func AuthMiddleware(tokenService TokenService, bootstrapToken string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Exempt sandbox endpoint from auth
		if r.URL.Path == "/sandbox" {
			next.ServeHTTP(w, r)
			return
		}

		// Extract Authorization header
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			log.Debug().Str("path", r.URL.Path).Msg("No Authorization header provided.")
			http.Error(w, `{"error":"missing authorization header"}`, http.StatusUnauthorized)
			return
		}

		// Extract Bearer token
		rawToken, err := extractBearerToken(authHeader)
		if err != nil {
			log.Warn().Str("path", r.URL.Path).Err(err).Msg("Invalid Authorization header format.")
			http.Error(w, fmt.Sprintf(`{"error":"invalid authorization header: %s"}`, err.Error()), http.StatusUnauthorized)
			return
		}

		// Check bootstrap token first (fast path, no DB lookup)
		if bootstrapToken != "" && rawToken == bootstrapToken {
			tokenCtx := &domain.TokenInfo{
				ID:        "bootstrap",
				TokenType: "bootstrap",
				ClientID:  "admin-ui",
				Roles:     []string{"ROLE_ADMIN"},
				ExpiresAt: time.Now().Add(24 * time.Hour),
			}
			newCtx := context.WithValue(r.Context(), domain.TokenContextKey, tokenCtx)
			log.Debug().Str("path", r.URL.Path).Msg("Bootstrap token validated successfully.")
			next.ServeHTTP(w, r.WithContext(newCtx))
			return
		}

		// Validate the token via TokenService
		tokenInfo, err := tokenService.ValidateAccessToken(r.Context(), rawToken)
		if err != nil {
			log.Warn().Str("path", r.URL.Path).Err(err).Msg("Token validation failed.")
			http.Error(w, `{"error":"invalid or expired token"}`, http.StatusUnauthorized)
			return
		}

		// Check token expiration (belt-and-suspenders: ValidateAccessToken should already check this)
		if time.Now().After(tokenInfo.ExpiresAt) {
			http.Error(w, `{"error":"token has expired"}`, http.StatusUnauthorized)
			return
		}

		// Check revocation
		if tokenInfo.IsRevoked {
			http.Error(w, `{"error":"token has been revoked"}`, http.StatusUnauthorized)
			return
		}

		// Convert domain.Token to domain.TokenInfo for context enrichment
		tokenCtx := &domain.TokenInfo{
			ID:        tokenInfo.ID,
			TokenType: tokenInfo.TokenType,
			ClientID:  tokenInfo.ClientID,
			UserID:    tokenInfo.UserID,
			Scope:     tokenInfo.Scope,
			IssuedAt:  tokenInfo.CreatedAt,
			ExpiresAt: tokenInfo.ExpiresAt,
			IsRevoked: tokenInfo.IsRevoked,
			Roles:     tokenInfo.Roles,
		}

		// Enrich context with authenticated token info
		newCtx := context.WithValue(r.Context(), domain.TokenContextKey, tokenCtx)

		log.Debug().Str("path", r.URL.Path).Str("userID", tokenInfo.UserID).
			Strs("roles", tokenInfo.Roles).Msg("Token validated successfully, request proceeding.")

		next.ServeHTTP(w, r.WithContext(newCtx))
	})
}

// extractBearerToken extracts the token from a Bearer authorization header.
func extractBearerToken(authHeader string) (string, error) {
	const prefix = "Bearer "
	if !strings.HasPrefix(authHeader, prefix) {
		return "", fmt.Errorf("authorization header must use Bearer scheme")
	}
	token := strings.TrimSpace(strings.TrimPrefix(authHeader, prefix))
	if token == "" {
		return "", fmt.Errorf("bearer token is empty")
	}
	return token, nil
}
