package middleware

import (
	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"go.opentelemetry.io/otel/trace"
)

// TraceIDMiddleware returns a Gin middleware that extracts the OpenTelemetry
// trace ID from the request context and injects it into the zerolog logger
// context so every downstream log.Ctx(ctx) call includes the trace_id field.
//
// Must be placed AFTER otelgin.Middleware so the OTel span is available.
func TraceIDMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		span := trace.SpanFromContext(c.Request.Context())
		if span != nil && span.SpanContext().HasTraceID() {
			traceID := span.SpanContext().TraceID().String()

			logger := zerolog.Ctx(c.Request.Context())
			if logger == nil {
				logger = &log.Logger
			}
			l := logger.With().Str("trace_id", traceID).Logger()
			c.Request = c.Request.WithContext(l.WithContext(c.Request.Context()))
		}
		c.Next()
	}
}
