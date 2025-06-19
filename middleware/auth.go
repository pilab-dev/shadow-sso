package middleware

import (
	"context"

	"connectrpc.com/connect"
	ssso "github.com/pilab-dev/shadow-sso"
	"github.com/pilab-dev/shadow-sso/internal/auth/rbac"
	"github.com/rs/zerolog/log"
)

const TokenContextKey = "auth_token"

func GetAuthenticatedTokenFromContext(ctx context.Context) (*ssso.TokenInfo, bool) {
	val := ctx.Value(TokenContextKey)

	if tokenInfo, ok := val.(*ssso.TokenInfo); ok {
		return tokenInfo, true
	}

	return nil, false
}

func NewAuthInterceptor(tokenService *ssso.TokenService) connect.Interceptor {
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

			return next(ctx, req)
		})
	})
}
