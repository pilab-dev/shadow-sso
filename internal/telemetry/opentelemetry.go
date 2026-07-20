package telemetry

import (
	"context"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/rs/zerolog/log"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	prometheusexporter "go.opentelemetry.io/otel/exporters/prometheus"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	"go.opentelemetry.io/otel/sdk/trace"
)

// InitTracer initializes the OpenTelemetry tracer provider with an OTLP gRPC exporter.
// Configuration is read from standard OTEL_* environment variables:
//   - OTEL_EXPORTER_OTLP_ENDPOINT    (default: http://localhost:4317)
//   - OTEL_EXPORTER_OTLP_HEADERS     (e.g. "Authorization=Bearer ...")
//   - OTEL_SERVICE_NAME              (overridden by serviceName parameter)
//   - OTEL_RESOURCE_ATTRIBUTES       (e.g. "deployment.environment=production")
//
// Pass an empty serviceName to rely solely on OTEL_SERVICE_NAME.
func InitTracer(ctx context.Context, serviceName string) (*trace.TracerProvider, error) {
	exporter, err := otlptracegrpc.New(ctx)
	if err != nil {
		return nil, err
	}

	res, err := resource.New(ctx,
		resource.WithFromEnv(), // pick up OTEL_RESOURCE_ATTRIBUTES
		resource.WithProcess(),
		resource.WithOS(),
	)
	if err != nil {
		log.Warn().Err(err).Msg("Failed to create OTel resource, using defaults")
		res = resource.Default()
	}

	if serviceName != "" {
		res, err = resource.Merge(res, resource.NewSchemaless(
			attribute.String("service.name", serviceName),
		))
		if err != nil {
			log.Warn().Err(err).Msg("Failed to merge service name into resource")
		}
	}

	bsp := trace.NewBatchSpanProcessor(exporter,
		trace.WithBatchTimeout(5*time.Second),
		trace.WithMaxExportBatchSize(512),
	)

	tp := trace.NewTracerProvider(
		trace.WithResource(res),
		trace.WithSpanProcessor(bsp),
	)
	otel.SetTracerProvider(tp)

	log.Info().
		Str("service_name", serviceName).
		Msg("OpenTelemetry TracerProvider initialized with OTLP gRPC exporter")
	return tp, nil
}

// InitMeterProvider initializes the OpenTelemetry meter provider with a Prometheus exporter.
func InitMeterProvider(reg prometheus.Registerer) (*metric.MeterProvider, error) {
	exporter, err := prometheusexporter.New(prometheusexporter.WithRegisterer(reg))
	if err != nil {
		return nil, err
	}

	mp := metric.NewMeterProvider(metric.WithReader(exporter))
	otel.SetMeterProvider(mp)
	log.Info().Msg("OpenTelemetry MeterProvider initialized with Prometheus exporter")
	return mp, nil
}

// Shutdown gracefully shuts down the tracer and meter providers.
func Shutdown(ctx context.Context, tp *trace.TracerProvider, mp *metric.MeterProvider) {
	if tp != nil {
		if err := tp.Shutdown(ctx); err != nil {
			log.Error().Err(err).Msg("Error shutting down OpenTelemetry TracerProvider")
		} else {
			log.Info().Msg("OpenTelemetry TracerProvider shut down successfully")
		}
	}
	if mp != nil {
		if err := mp.Shutdown(ctx); err != nil {
			log.Error().Err(err).Msg("Error shutting down OpenTelemetry MeterProvider")
		} else {
			log.Info().Msg("OpenTelemetry MeterProvider shut down successfully")
		}
	}
}
