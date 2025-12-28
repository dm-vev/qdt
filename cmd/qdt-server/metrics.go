package main

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

type Metrics struct {
	sessions   prometheus.Gauge
	packets    *prometheus.CounterVec
	bytes      *prometheus.CounterVec
	drops      *prometheus.CounterVec
	handshakes *prometheus.CounterVec
}

func NewMetrics() *Metrics {
	return &Metrics{
		sessions: promauto.NewGauge(prometheus.GaugeOpts{
			Name: "qdt_sessions_active",
			Help: "Active QDT sessions",
		}),
		packets: promauto.NewCounterVec(prometheus.CounterOpts{
			Name: "qdt_packets_total",
			Help: "QDT packets",
		}, []string{"direction"}),
		bytes: promauto.NewCounterVec(prometheus.CounterOpts{
			Name: "qdt_bytes_total",
			Help: "QDT bytes",
		}, []string{"direction"}),
		drops: promauto.NewCounterVec(prometheus.CounterOpts{
			Name: "qdt_drops_total",
			Help: "QDT drops",
		}, []string{"reason"}),
		handshakes: promauto.NewCounterVec(prometheus.CounterOpts{
			Name: "qdt_handshakes_total",
			Help: "QDT handshake results",
		}, []string{"result"}),
	}
}
