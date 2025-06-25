package log

import "context"

// Logger defines a standard interface for logging.
// Inspired by common logging library patterns.
type Logger interface {
	Debug(ctx context.Context, msg string, fields ...map[string]interface{})
	Info(ctx context.Context, msg string, fields ...map[string]interface{})
	Warn(ctx context.Context, msg string, fields ...map[string]interface{})
	Error(ctx context.Context, msg string, err error, fields ...map[string]interface{})
	Fatal(ctx context.Context, msg string, err error, fields ...map[string]interface{}) // Typically os.Exit(1) is called by underlying logger
	With(fields map[string]interface{}) Logger                                         // Returns a new logger with added structured fields
}
