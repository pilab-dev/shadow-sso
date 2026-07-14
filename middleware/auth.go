package middleware

import (
	"context"
	"fmt"
	"strings"
	"time"

	"connectrpc.com/connect"
	"github.com/pilab-dev/shadow-sso/domain"
	"github.com/pilab-dev/shadow-sso/services"
	"github.com/rs/zerolog/log"
)

// publicProcedures lists RPC procedures that do not require authentication.
// These are procedures that either handle authentication themselves (e.g., Login)
// or are explicitly designed to be unauthenticated.
var publicProcedures = map[string]bool{
	// AuthService - authentication endpoints
	"/sso.v1.AuthService/Login":                    true,
	"/sso.v1.AuthService/CompleteWebAuthnLogin":    true,

	// UserService - self-service registration
	"/sso.v1.UserService/RegisterUser": true,

	// TwoFactorService - setup initiation (uses session-based auth, not JWT)
	"/sso.v1.TwoFactorService/InitiateTOTPSetup":      true,
	"/sso.v1.TwoFactorService/VerifyAndEnableTOTP":    true,
	"/sso.v1.TwoFactorService/InitiateHOTPSetup":      true,
	"/sso.v1.TwoFactorService/VerifyAndEnableHOTP":    true,
	"/sso.v1.TwoFactorService/InitiateEmailMFASetup":  true,
	"/sso.v1.TwoFactorService/VerifyAndEnableEmailMFA": true,
	"/sso.v1.TwoFactorService/InitiatePushMFASetup":   true,
	"/sso.v1.TwoFactorService/VerifyAndEnablePushMFA":  true,

	// FederationService - federated login initiation and callback
	"/sso.v1.FederationService/InitiateFederatedLogin":    true,
	"/sso.v1.FederationService/HandleFederatedCallback":   true,
	"/sso.v1.FederationService/AuthenticateDirect":        true,
	"/sso.v1.FederationService/PromptMergeFederatedAccount":  true,
	"/sso.v1.FederationService/ConfirmMergeFederatedAccount": true,
}

// rolesContextKeyType is a private type for context key to avoid collisions.
type rolesContextKeyType string

// RolesContextKey is the context key used to store user roles for the RBAC interceptor.
const RolesContextKey rolesContextKeyType = "user_roles"

// NewAuthInterceptor creates a Connect interceptor for authentication.
// It extracts and validates JWT tokens from the Authorization header,
// and enriches the context with the authenticated token info and user roles.
func NewAuthInterceptor(tokenService services.TokenService) connect.Interceptor {
	return connect.UnaryInterceptorFunc(func(next connect.UnaryFunc) connect.UnaryFunc {
		return connect.UnaryFunc(func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
			procedure := req.Spec().Procedure // e.g., "/sso.v1.UserService/ListUsers"

			// Check if this procedure is explicitly public (no auth required)
			if publicProcedures[procedure] {
				log.Debug().Str("procedure", procedure).Msg("Public procedure, skipping authentication.")
				return next(ctx, req)
			}

			// Extract Authorization header
			authHeader := req.Header().Get("Authorization")
			if authHeader == "" {
				log.Debug().Str("procedure", procedure).Msg("No Authorization header provided.")
				return nil, connect.NewError(connect.CodeUnauthenticated,
					fmt.Errorf("missing authorization header"))
			}

			// Extract Bearer token
			rawToken, err := extractBearerToken(authHeader)
			if err != nil {
				log.Warn().Str("procedure", procedure).Err(err).Msg("Invalid Authorization header format.")
				return nil, connect.NewError(connect.CodeUnauthenticated,
					fmt.Errorf("invalid authorization header: %w", err))
			}

			// Validate the token via TokenService
			tokenInfo, err := tokenService.ValidateAccessToken(ctx, rawToken)
			if err != nil {
				log.Warn().Str("procedure", procedure).Err(err).Msg("Token validation failed.")
				return nil, connect.NewError(connect.CodeUnauthenticated,
					fmt.Errorf("invalid or expired token: %w", err))
			}

			// Check token expiration (belt-and-suspenders: ValidateAccessToken should already check this)
			if time.Now().After(tokenInfo.ExpiresAt) {
				return nil, connect.NewError(connect.CodeUnauthenticated,
					fmt.Errorf("token has expired"))
			}

			// Check revocation
			if tokenInfo.IsRevoked {
				return nil, connect.NewError(connect.CodeUnauthenticated,
					fmt.Errorf("token has been revoked"))
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
			newCtx := context.WithValue(ctx, domain.TokenContextKey, tokenCtx)

			// Enrich context with user roles for RBAC interceptor
			if len(tokenInfo.Roles) > 0 {
				newCtx = context.WithValue(newCtx, RolesContextKey, tokenInfo.Roles)
			}

			log.Debug().Str("procedure", procedure).Str("userID", tokenInfo.UserID).
				Strs("roles", tokenInfo.Roles).Msg("Token validated successfully, request proceeding.")

			return next(newCtx, req)
		})
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
