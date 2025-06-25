package tracing

import (
	"context"
	"os" // For InitTracerProvider if serviceName needs env var or default

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/stdout/stdouttrace"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.20.0" // Using specific version
	"go.opentelemetry.io/otel/trace"
)

// Tracer is a global tracer instance for the application.
var Tracer trace.Tracer

// defaultServiceName is used if no service name is provided to InitTracerProvider.
const (
	defaultServiceName = "shadow-sso"
	tracerName         = "github.com/pilab-dev/shadow-sso" // Or a more specific component name
)

// InitTracerProvider initializes an OpenTelemetry TracerProvider.
// It sets up an exporter (stdout for now), a resource, and registers the provider globally.
func InitTracerProvider(serviceNameInput string) (*sdktrace.TracerProvider, error) {
	var serviceName string
	if serviceNameInput != "" {
		serviceName = serviceNameInput
	} else {
		envServiceName := os.Getenv("OTEL_SERVICE_NAME")
		if envServiceName != "" {
			serviceName = envServiceName
		} else {
			serviceName = defaultServiceName
		}
	}

	// Create a new stdout exporter for traces.
	// WithPrettyPrint makes the output human-readable.
	exporter, err := stdouttrace.New(stdouttrace.WithPrettyPrint())
	if err != nil {
		return nil, err
	}

	// Define the resource for this service.
	// A resource is a collection of attributes that identify the entity producing telemetry.
	res, err := resource.New(
		context.Background(),
		resource.WithAttributes(
			semconv.ServiceNameKey.String(serviceName),
			// You can add more attributes here, like service version, environment, etc.
			// semconv.ServiceVersionKey.String("v0.1.0"),
		),
	)
	if err != nil {
		return nil, err
	}

	// Create a new TracerProvider.
	// WithBatcher configures the exporter to send traces in batches.
	// WithResource associates the defined resource with all traces produced by this provider.
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
		sdktrace.WithResource(res),
		// TODO: Add a sampler for production use, e.g., sdktrace.TraceIDRatioBased(0.1) for 10% sampling
		// For development, ParentBased(AlwaysSample()) is okay.
		sdktrace.WithSampler(sdktrace.AlwaysSample()), // Sample all traces for now
	)

	// Set the global TracerProvider.
	otel.SetTracerProvider(tp)

	// Set the global TextMapPropagator to ensure trace context propagation.
	// TraceContext propagator handles W3C Trace Context headers (traceparent, tracestate).
	// Baggage propagator handles W3C Baggage header.
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))

	// Initialize the global Tracer variable.
	// The tracer name should be the instrumentation library name, not the service name.
	// Example: "github.com/gin-gonic/gin" for Gin middleware, or your app's module path.
	Tracer = otel.Tracer(tracerName)

	return tp, nil
}
