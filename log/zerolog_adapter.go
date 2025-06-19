package log

import (
	"context"
	"os"
	"time"

	"github.com/rs/zerolog"
	"go.opentelemetry.io/otel/trace" // Added import for tracing
)

// zerologAdapter wraps a zerolog.Logger to implement the custom Logger interface.
type zerologAdapter struct {
	logger zerolog.Logger
}

// NewZerologAdapter creates a new Logger implemented with zerolog.
func NewZerologAdapter(level zerolog.Level, pretty bool) Logger {
	var zlog zerolog.Logger
	if pretty {
		zlog = zerolog.New(zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: time.RFC3339}).
			Level(level).
			With().
			Timestamp().
			Logger()
	} else {
		zlog = zerolog.New(os.Stderr).
			Level(level).
			With().
			Timestamp().
			Logger()
	}
	return &zerologAdapter{logger: zlog}
}

// addTraceInfo checks for a valid span in context and adds trace_id and span_id to the log event.
func addTraceInfo(ctx context.Context, event *zerolog.Event) *zerolog.Event {
	span := trace.SpanFromContext(ctx)
	if span.SpanContext().IsValid() {
		event = event.Str("trace_id", span.SpanContext().TraceID().String()).
			Str("span_id", span.SpanContext().SpanID().String())
	}
	return event
}

func (z *zerologAdapter) Debug(ctx context.Context, msg string, fields ...map[string]interface{}) {
	event := z.logger.Debug()
	event = addTraceInfo(ctx, event)
	for _, f := range fields {
		event = event.Fields(f)
	}
	event.Msg(msg)
}

func (z *zerologAdapter) Info(ctx context.Context, msg string, fields ...map[string]interface{}) {
	event := z.logger.Info()
	event = addTraceInfo(ctx, event)
	for _, f := range fields {
		event = event.Fields(f)
	}
	event.Msg(msg)
}

func (z *zerologAdapter) Warn(ctx context.Context, msg string, fields ...map[string]interface{}) {
	event := z.logger.Warn()
	event = addTraceInfo(ctx, event)
	for _, f := range fields {
		event = event.Fields(f)
	}
	event.Msg(msg)
}

func (z *zerologAdapter) Error(ctx context.Context, msg string, err error, fields ...map[string]interface{}) {
	event := z.logger.Error().Err(err)
	event = addTraceInfo(ctx, event)
	for _, f := range fields {
		event = event.Fields(f)
	}
	event.Msg(msg)
}

func (z *zerologAdapter) Fatal(ctx context.Context, msg string, err error, fields ...map[string]interface{}) {
	event := z.logger.Fatal().Err(err) // zerolog.Fatal() will os.Exit
	event = addTraceInfo(ctx, event)
	for _, f := range fields {
		event = event.Fields(f)
	}
	event.Msg(msg)
}

// With returns a new logger with the provided fields added to its context.
// Trace information will be added per-call, not to the With context, to ensure it's current.
func (z *zerologAdapter) With(fields map[string]interface{}) Logger {
	newLogger := z.logger.With().Fields(fields).Logger()
	return &zerologAdapter{logger: newLogger}
}
