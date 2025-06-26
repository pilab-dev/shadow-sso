package telemetry

import (
	"context"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/rs/zerolog/log"
	"go.opentelemetry.io/otel"
	prometheusexporter "go.opentelemetry.io/otel/exporters/prometheus"
	"go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/trace"
)

// InitTracer initializes the OpenTelemetry tracer provider.
func InitTracer() (*trace.TracerProvider, error) {
	// For this example, we'll use a simple setup.
	// In a production environment, you would configure exporters (e.g., Jaeger, OTLP).
	tp := trace.NewTracerProvider()
	otel.SetTracerProvider(tp)
	log.Info().Msg("OpenTelemetry TracerProvider initialized")
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
