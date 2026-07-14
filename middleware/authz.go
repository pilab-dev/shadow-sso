package middleware

import (
	"context"
	"fmt"

	"connectrpc.com/connect"
	"github.com/pilab-dev/shadow-sso/internal/auth/rbac" // For rbac.HasPermission and rbac.MethodPermissions
	"github.com/rs/zerolog/log"
)

// GetRolesFromContext extracts user roles from the context.
// The roles are set by the auth interceptor (middleware/auth.go) during authentication.
func GetRolesFromContext(ctx context.Context) ([]string, bool) {
	if roles, ok := ctx.Value(RolesContextKey).([]string); ok {
		return roles, true
	}
	return nil, false
}

// NewAuthorizationInterceptor creates a Connect interceptor for RBAC authorization.
// It should run *after* the authentication interceptor.
func NewAuthorizationInterceptor() connect.Interceptor {
	return connect.UnaryInterceptorFunc(func(next connect.UnaryFunc) connect.UnaryFunc {
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

			userRoles, ok := GetRolesFromContext(ctx)
			if !ok {
				// This means auth interceptor did not set roles, or user is not authenticated.
				log.Warn().Str("procedure", procedure).Msg("User authenticated but no roles found in context for authorization check.")
				return nil, connect.NewError(connect.CodePermissionDenied, fmt.Errorf("permission denied: user roles not found in context"))
			}

			if !rbac.HasPermission(userRoles, requiredPermission) {
				log.Warn().Str("procedure", procedure).Strs("user_roles", userRoles).
					Str("required_permission", requiredPermission).Msg("Permission denied for user.")
				return nil, connect.NewError(connect.CodePermissionDenied,
					fmt.Errorf("permission denied: required permission '%s' not met by roles %v", requiredPermission, userRoles))
			}

			log.Debug().Str("procedure", procedure).Strs("user_roles", userRoles).
				Str("required_permission", requiredPermission).Msg("Permission granted by RBAC interceptor.")
			return next(ctx, req)
		})
	})
}
