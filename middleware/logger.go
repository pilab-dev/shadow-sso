package middleware

import (
	"time"

	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"
)

// ZerologLogger returns a Gin middleware that logs HTTP requests using zerolog.
// It uses the global zerolog.Logger which is already configured (JSON or pretty)
// based on the SSSO_JSON_LOG environment variable.
func ZerologLogger() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		path := c.Request.URL.Path
		raw := c.Request.URL.RawQuery

		// Process request
		c.Next()

		// Skip health check endpoints to reduce noise
		if path == "/healthz" || path == "/readyz" {
			return
		}

		latency := time.Since(start)
		statusCode := c.Writer.Status()
		clientIP := c.ClientIP()
		method := c.Request.Method

		event := log.Info()
		if statusCode >= 500 {
			event = log.Error()
		} else if statusCode >= 400 {
			event = log.Warn()
		}

		event.
			Str("http_method", method).
			Str("path", path).
			Int("status", statusCode).
			Dur("latency", latency).
			Int("size", c.Writer.Size()).
			Str("ip", clientIP).
			Str("user_agent", c.Request.UserAgent())

		if raw != "" {
			event.Str("query", raw)
		}

		event.Msg("HTTP request")
	}
}
