package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/pprof"
	"os"
	"time"

	"github.com/pilab-dev/shadow-sso/services"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rs/zerolog/log"
)

// StartManagementServer creates and starts a plain net/http server for management endpoints.
// This server runs on a separate port from the main SSO server and provides:
//   - /healthz — liveness probe (always 200)
//   - /readyz  — readiness probe (pings MongoDB)
//   - /metrics — Prometheus metrics (OpenMetrics format)
//   - /debug/pprof/* — Go pprof endpoints (only if SSSO_PPROF_ENABLED=true)
//
// No CORS or auth middleware — these are kubelet probe endpoints.
func StartManagementServer(address string, repoProvider services.RepositoryProvider, registry *prometheus.Registry) *http.Server {
	mux := http.NewServeMux()

	// /healthz — liveness check, no DB dependency
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	})

	// /readyz — readiness check, pings MongoDB
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()

		w.Header().Set("Content-Type", "application/json")

		if err := repoProvider.Ping(ctx); err != nil {
			log.Warn().Err(err).Msg("Management server: readiness check failed")
			w.WriteHeader(http.StatusServiceUnavailable)
			_ = json.NewEncoder(w).Encode(map[string]string{"status": "not ready"})
			return
		}

		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	})

	// /metrics — Prometheus metrics endpoint
	mux.Handle("/metrics", promhttp.HandlerFor(registry, promhttp.HandlerOpts{
		EnableOpenMetrics: true,
	}))

	// /debug/pprof/* — only if SSSO_PPROF_ENABLED=true (checked at init time)
	if os.Getenv("SSSO_PPROF_ENABLED") == "true" {
		log.Info().Msg("pprof endpoints enabled on management server")
		mux.HandleFunc("/debug/pprof/", pprof.Index)
		mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
		mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
		mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
		mux.HandleFunc("/debug/pprof/trace", pprof.Trace)
	}

	srv := &http.Server{
		Addr:              address,
		Handler:           mux,
		ReadHeaderTimeout: 3 * time.Second,
	}

	go func() {
		log.Info().Str("addr", address).Msg("Management server starting")
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Error().Err(err).Str("addr", address).Msg("Management server failed")
		}
	}()

	return srv
}
