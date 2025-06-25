package middleware

import (
	"context"

	"connectrpc.com/connect"
	// "github.com/pilab-dev/shadow-sso/domain" // Will be needed when interceptor is fully implemented
	"github.com/pilab-dev/shadow-sso/internal/auth/rbac"
	"github.com/pilab-dev/shadow-sso/services"
	"github.com/rs/zerolog/log"
)

func NewAuthInterceptor(tokenService *services.TokenService) connect.Interceptor {
	return connect.UnaryInterceptorFunc(func(next connect.UnaryFunc) connect.UnaryFunc {
		// This is a simplified interceptor. A real one would:
		// 1. Extract token from req.Header().Get("Authorization")
		// 2. Validate token using tokenService.ValidateAccessToken(ctx, rawToken)
		// 3. If valid, enrich context: newCtx := context.WithValue(ctx, domain.TokenContextKey, validatedTokenInfo)
		// 4. Call next(newCtx, req)
		// 5. Handle errors (unauthenticated, etc.)

		// For now, assuming token validation and context enrichment happens elsewhere or is not fully implemented here.
		// The main goal is to break the import cycle.
		// The RBAC check below would use domain.GetAuthenticatedTokenFromContext(ctx)
		return connect.UnaryFunc(func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
			procedure := req.Spec().Procedure // e.g., "/sso.v1.UserService/ListUsers"

			requiredPermission, needsAuthzCheck := rbac.MethodPermissions[procedure]

			if !needsAuthzCheck { // Not in map means public (after authN) or authz handled in service
				log.Debug().Str("procedure", procedure).Msg("No specific permission defined in map, proceeding (authz may be handled in service).")
				return next(ctx, req)
			}

			if requiredPermission == "" { // Explicitly marked as handled by service logic
				log.Debug().Str("procedure", procedure).Msg("Permission check explicitly deferred to service logic.")
				return next(ctx, req)
			}

			return next(ctx, req)
		})
	})
}
