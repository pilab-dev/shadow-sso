// ! TODO: Check the validity of the token
package openidv2_1

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/pilab-dev/shadow-sso/services"
	"github.com/rs/zerolog/log"
	"go.opentelemetry.io/otel"
)

const AuthUserIDKey = "auth-user-id"

// extractJWTFromHeader extracts the JWT from the Authorization header.
func extractJWTFromHeader(bearerToken string) (string, error) {
	const prefix = "Bearer "
	if strings.HasPrefix(bearerToken, prefix) {
		return strings.TrimPrefix(bearerToken, prefix), nil
	}
	return "", errors.New("invalid bearer token")
}

func UserAuthMiddleware(tokenService services.TokenService) gin.HandlerFunc {
	return func(c *gin.Context) {
		tp := otel.GetTracerProvider()
		ctx, span := tp.Tracer("").Start(c.Request.Context(), "JWTAuthMiddleware")

		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			span.End()

			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"code": "missing_authorization_header",
				"msg":  "Missing Authorization header",
			})

			return
		}

		jwtToken, err := extractJWTFromHeader(authHeader)
		log.Warn().Ctx(ctx).Msg("Token is not introspected. With a zero-trust architecture, we should introspect the token.")

		if err != nil {
			span.RecordError(fmt.Errorf("invalid authorization header: %w", err))
			span.End()

			c.AbortWithStatusJSON(401, gin.H{
				"code": "invalid_authorization_header",
				"msg":  "Invalid Authorization header",
			})

			return
		}

		token, err := tokenService.ValidateAccessToken(c.Request.Context(), jwtToken)
		if err != nil {
			log.Ctx(c.Request.Context()).Error().Ctx(ctx).Err(err).Msg("failed to validate JWT token")

			span.RecordError(err)
			span.End()

			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"code": "invalid_token",
				"msg":  "Invalid token",
			})

			return
		}

		span.End()

		c.Set(AuthUserIDKey, token.UserID)
		c.Set("scope", token.Scope)

		c.Next()
	}
}
