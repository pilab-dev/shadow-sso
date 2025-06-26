package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/rs/zerolog/log"
)

var (
	TokensCreatedTotal    prometheus.Counter
	TokensRefreshedTotal  prometheus.Counter
	ActiveSessionsGauge   prometheus.Gauge
	LoginSuccessTotal     prometheus.Counter
	LoginFailureTotal     prometheus.Counter
	UserRegisteredTotal   prometheus.Counter
	// Add more metrics here as needed
)

// InitCustomMetrics initializes and registers custom Prometheus metrics.
// It should be called once at application startup.
func InitCustomMetrics(reg prometheus.Registerer) {
	TokensCreatedTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "sso_tokens_created_total",
		Help: "Total number of tokens created.",
	})
	TokensRefreshedTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "sso_tokens_refreshed_total",
		Help: "Total number of tokens refreshed.",
	})
	ActiveSessionsGauge = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "sso_active_sessions_gauge",
		Help: "Current number of active user sessions.",
	})
	LoginSuccessTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "sso_logins_success_total",
		Help: "Total number of successful logins.",
	})
	LoginFailureTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "sso_logins_failure_total",
		Help: "Total number of failed logins.",
	})
	UserRegisteredTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "sso_users_registered_total",
		Help: "Total number of users registered.",
	})

	// Register metrics
	if reg != nil {
		err := reg.Register(TokensCreatedTotal)
		if err != nil {
			log.Warn().Err(err).Msg("Failed to register TokensCreatedTotal metric")
		}
		err = reg.Register(TokensRefreshedTotal)
		if err != nil {
			log.Warn().Err(err).Msg("Failed to register TokensRefreshedTotal metric")
		}
		err = reg.Register(ActiveSessionsGauge)
		if err != nil {
			log.Warn().Err(err).Msg("Failed to register ActiveSessionsGauge metric")
		}
		err = reg.Register(LoginSuccessTotal)
		if err != nil {
			log.Warn().Err(err).Msg("Failed to register LoginSuccessTotal metric")
		}
		err = reg.Register(LoginFailureTotal)
		if err != nil {
			log.Warn().Err(err).Msg("Failed to register LoginFailureTotal metric")
		}
		err = reg.Register(UserRegisteredTotal)
		if err != nil {
			log.Warn().Err(err).Msg("Failed to register UserRegisteredTotal metric")
		}
		log.Info().Msg("Custom Prometheus metrics registered.")
	} else {
		log.Error().Msg("Prometheus registry is nil, cannot register custom metrics.")
	}
}
