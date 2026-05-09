package metrics

import (
	"net/http"
	"runtime"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type Registry struct {
	registry *prometheus.Registry

	ConnectionsTotal       *prometheus.CounterVec
	AuthAttemptsTotal      *prometheus.CounterVec
	BackendDialErrorsTotal *prometheus.CounterVec
	BytesTransferredTotal  *prometheus.CounterVec
	ConnectionsActive      *prometheus.GaugeVec
	ConnectionDuration     *prometheus.HistogramVec
	BackendDialDuration    *prometheus.HistogramVec
	AuthDuration           *prometheus.HistogramVec
}

func New() *Registry {
	registry := prometheus.NewRegistry()

	m := &Registry{
		registry: registry,
		ConnectionsTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "ssh_proxy_connections_total",
				Help: "Total SSH proxy session outcomes by backend and auth method.",
			},
			[]string{"backend", "auth_method", "result"},
		),
		AuthAttemptsTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "ssh_proxy_auth_attempts_total",
				Help: "Total SSH authentication attempts handled by the proxy.",
			},
			[]string{"method", "result", "backend"},
		),
		BackendDialErrorsTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "ssh_proxy_backend_dial_errors_total",
				Help: "Total backend connection failures grouped by backend and reason.",
			},
			[]string{"backend", "reason"},
		),
		BytesTransferredTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "ssh_proxy_bytes_transferred_total",
				Help: "Total bytes transferred through proxied SSH channels.",
			},
			[]string{"backend", "direction"},
		),
		ConnectionsActive: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "ssh_proxy_connections_active",
				Help: "Current active proxied SSH sessions by backend.",
			},
			[]string{"backend"},
		),
		ConnectionDuration: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "ssh_proxy_connection_duration_seconds",
				Help:    "Lifecycle duration of proxied SSH sessions.",
				Buckets: prometheus.DefBuckets,
			},
			[]string{"backend"},
		),
		BackendDialDuration: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "ssh_proxy_backend_dial_duration_seconds",
				Help:    "Duration of backend TCP dial plus SSH authentication attempts.",
				Buckets: prometheus.DefBuckets,
			},
			[]string{"backend"},
		),
		AuthDuration: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "ssh_proxy_auth_duration_seconds",
				Help:    "Duration of client authentication handled by the proxy.",
				Buckets: prometheus.DefBuckets,
			},
			[]string{"method"},
		),
	}

	registry.MustRegister(
		m.ConnectionsTotal,
		m.AuthAttemptsTotal,
		m.BackendDialErrorsTotal,
		m.BytesTransferredTotal,
		m.ConnectionsActive,
		m.ConnectionDuration,
		m.BackendDialDuration,
		m.AuthDuration,
		prometheus.NewGaugeFunc(
			prometheus.GaugeOpts{
				Name: "ssh_proxy_goroutines_total",
				Help: "Current number of Go goroutines in the proxy process.",
			},
			func() float64 {
				return float64(runtime.NumGoroutine())
			},
		),
	)

	return m
}

func (m *Registry) Handler() http.Handler {
	return promhttp.HandlerFor(m.registry, promhttp.HandlerOpts{})
}

func (m *Registry) RecordConnectionResult(backend, authMethod, result string) {
	if m == nil {
		return
	}
	m.ConnectionsTotal.WithLabelValues(backend, authMethod, result).Inc()
}

func (m *Registry) RecordAuthAttempt(method, result, backend string, duration time.Duration) {
	if m == nil {
		return
	}
	m.AuthAttemptsTotal.WithLabelValues(method, result, backend).Inc()
	m.AuthDuration.WithLabelValues(method).Observe(duration.Seconds())
}

func (m *Registry) RecordBackendDial(backend string, duration time.Duration, reason string) {
	if m == nil {
		return
	}
	m.BackendDialDuration.WithLabelValues(backend).Observe(duration.Seconds())
	if reason != "" {
		m.BackendDialErrorsTotal.WithLabelValues(backend, reason).Inc()
	}
}

func (m *Registry) AddBytes(backend, direction string, count int64) {
	if m == nil || count <= 0 {
		return
	}
	m.BytesTransferredTotal.WithLabelValues(backend, direction).Add(float64(count))
}

func (m *Registry) IncActive(backend string) {
	if m == nil {
		return
	}
	m.ConnectionsActive.WithLabelValues(backend).Inc()
}

func (m *Registry) DecActive(backend string) {
	if m == nil {
		return
	}
	m.ConnectionsActive.WithLabelValues(backend).Dec()
}

func (m *Registry) ObserveConnectionDuration(backend string, duration time.Duration) {
	if m == nil {
		return
	}
	m.ConnectionDuration.WithLabelValues(backend).Observe(duration.Seconds())
}
