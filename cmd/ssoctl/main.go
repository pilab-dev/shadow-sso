package main

import (
	"context"
	"log" // Standard log for fatal errors if custom logger isn't ready

	"github.com/pilab-dev/shadow-sso/cmd/ssoctl/cmd" // Path to your cmd package
	"github.com/pilab-dev/shadow-sso/tracing"       // Import the new tracing package
)

func main() {
	// Initialize OpenTelemetry TracerProvider
	tp, err := tracing.InitTracerProvider("shadow-sso-ssoctl") // Service name for the CLI tool
	if err != nil {
		log.Fatalf("Failed to initialize TracerProvider: %v", err)
	}

	// Defer shutdown of the TracerProvider to ensure all buffered spans are flushed.
	// Use a background context for shutdown as the main context might have already been canceled.
	defer func() {
		if err := tp.Shutdown(context.Background()); err != nil {
			log.Printf("Error shutting down TracerProvider: %v", err)
		}
	}()

	// The global Tracer is initialized in tracing/tracer.go's InitTracerProvider or init()
	// Example usage (though typically done within specific commands/functions):
	// _, span := tracing.Tracer.Start(context.Background(), "ssoctl-main")
	// defer span.End()
	// span.SetAttributes(attribute.String("cli.command", "main_execution_start"))

	cmd.Execute()
}
