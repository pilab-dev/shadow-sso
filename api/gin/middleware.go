// ! TODO: Check the validity of the token
package sssogin

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	ssso "github.com/pilab-dev/shadow-sso"
	"github.com/rs/zerolog/log"
	"go.opentelemetry.io/otel"
)

const AuthUserIDKey = "auth-user-id"

var ErrInvalidToken = errors.New("invalid JWT token")

// ParseClaims parses the JWT and returns the claims.
func ParseClaims(jwtToken string) (jwt.MapClaims, error) {
	claims := make(jwt.MapClaims)

	token, err := jwt.ParseWithClaims(jwtToken, claims, func(token *jwt.Token) (any, error) {
		// Normally, you would validate the token's signature here.
		// For example, return the public key for RS256.
		return []byte("your-256-bit-secret"), nil
	})
	if err != nil {
		if errors.Is(err, jwt.ErrTokenMalformed) {
			return nil, err
		} else {
			err = fmt.Errorf("failed to parse JWT token: %w", err)

			log.Error().Err(err).Type("errType", err).Send()

			return nil, err
		}
	}

	if token.Valid {
		return claims, nil
	}

	switch {
	case token.Valid:
		fmt.Println("You look nice today")
	case errors.Is(err, jwt.ErrTokenMalformed):
		fmt.Println("That's not even a token")
	case errors.Is(err, jwt.ErrTokenSignatureInvalid): // Invalid signature
		fmt.Println("Invalid signature")
	case errors.Is(err, jwt.ErrTokenExpired) || errors.Is(err, jwt.ErrTokenNotValidYet): // Token is either expired or not active yet
		fmt.Println("Timing is everything")
	default:
		fmt.Println("Couldn't handle this token:", err)
	}

	return nil, ErrInvalidToken
}

// extractJWTFromHeader extracts the JWT from the Authorization header.
func extractJWTFromHeader(bearerToken string) (string, error) {
	const prefix = "Bearer "
	if strings.HasPrefix(bearerToken, prefix) {
		return strings.TrimPrefix(bearerToken, prefix), nil
	}
	return "", errors.New("invalid bearer token")
}

func UserAuthMiddleware(tokenService *ssso.TokenService) gin.HandlerFunc {
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
