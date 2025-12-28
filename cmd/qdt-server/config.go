package main

import (
	"fmt"
	"net"
	"runtime"
	"time"

	"qdt/internal/config"
	"qdt/pkg/qdt"
)

type Config struct {
	Addr               string        `yaml:"addr"`
	TLSCert            string        `yaml:"tls_cert"`
	TLSKey             string        `yaml:"tls_key"`
	Token              string        `yaml:"token"`
	MTU                int           `yaml:"mtu"`
	TunName            string        `yaml:"tun_name"`
	PoolCIDR           string        `yaml:"pool_cidr"`
	GatewayIP          string        `yaml:"gateway_ip"`
	DNS                []string      `yaml:"dns"`
	MetricsAddr        string        `yaml:"metrics_addr"`
	HealthAddr         string        `yaml:"health_addr"`
	PprofAddr          string        `yaml:"pprof_addr"`
	LogLevel           string        `yaml:"log_level"`
	LogJSON            bool          `yaml:"log_json"`
	SessionTimeout     time.Duration `yaml:"session_timeout"`
	MaxReassemblyBytes int           `yaml:"max_reassembly_bytes"`
	RateLimit          struct {
		PPS   int `yaml:"pps"`
		Burst int `yaml:"burst"`
	} `yaml:"rate_limit"`
	HandshakeRate struct {
		PPS   int `yaml:"pps"`
		Burst int `yaml:"burst"`
	} `yaml:"handshake_rate"`
	HandshakeIPRate struct {
		PPS   int           `yaml:"pps"`
		Burst int           `yaml:"burst"`
		TTL   time.Duration `yaml:"ttl"`
	} `yaml:"handshake_ip_rate"`
	SendWorkers   int `yaml:"send_workers"`
	SendQueue     int `yaml:"send_queue"`
	SendBatch     int `yaml:"send_batch"`
	SessionShards int `yaml:"session_shards"`
	NAT           struct {
		Enabled       bool   `yaml:"enabled"`
		ExternalIface string `yaml:"external_iface"`
	} `yaml:"nat"`
}

func LoadConfig(path string) (Config, error) {
	cfg := Config{}
	if err := config.Load(path, &cfg); err != nil {
		return Config{}, err
	}
	applyDefaults(&cfg)
	if err := validateConfig(cfg); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func applyDefaults(cfg *Config) {
	if cfg.Addr == "" {
		cfg.Addr = ":443"
	}
	if cfg.MTU == 0 {
		cfg.MTU = qdt.DefaultMTU
	}
	if cfg.TunName == "" {
		cfg.TunName = "qdt0"
	}
	if cfg.PoolCIDR == "" {
		cfg.PoolCIDR = "10.8.0.0/24"
	}
	if cfg.GatewayIP == "" {
		cfg.GatewayIP = defaultGateway(cfg.PoolCIDR)
	}
	if cfg.MetricsAddr == "" {
		cfg.MetricsAddr = ":9100"
	}
	if cfg.HealthAddr == "" {
		cfg.HealthAddr = ":9200"
	}
	if cfg.PprofAddr == "" {
		cfg.PprofAddr = ""
	}
	if cfg.SessionTimeout == 0 {
		cfg.SessionTimeout = 2 * time.Minute
	}
	if cfg.MaxReassemblyBytes == 0 {
		cfg.MaxReassemblyBytes = qdt.DefaultMaxReassembly
	}
	if cfg.RateLimit.PPS == 0 {
		cfg.RateLimit.PPS = 10000
	}
	if cfg.RateLimit.Burst == 0 {
		cfg.RateLimit.Burst = 20000
	}
	if cfg.HandshakeRate.PPS == 0 {
		cfg.HandshakeRate.PPS = 100
	}
	if cfg.HandshakeRate.Burst == 0 {
		cfg.HandshakeRate.Burst = 200
	}
	if cfg.HandshakeIPRate.PPS == 0 {
		cfg.HandshakeIPRate.PPS = 20
	}
	if cfg.HandshakeIPRate.Burst == 0 {
		cfg.HandshakeIPRate.Burst = 40
	}
	if cfg.HandshakeIPRate.TTL == 0 {
		cfg.HandshakeIPRate.TTL = 1 * time.Minute
	}
	if cfg.SendWorkers == 0 {
		cfg.SendWorkers = runtime.NumCPU()
	}
	if cfg.SendQueue == 0 {
		cfg.SendQueue = 4096
	}
	if cfg.SendBatch == 0 {
		cfg.SendBatch = 4
	}
	if cfg.SessionShards == 0 {
		cfg.SessionShards = runtime.NumCPU() * 4
	}
}

func validateConfig(cfg Config) error {
	if cfg.TLSCert == "" || cfg.TLSKey == "" {
		return fmt.Errorf("tls_cert and tls_key are required")
	}
	if cfg.Token == "" {
		return fmt.Errorf("token is required")
	}
	if cfg.GatewayIP == "" {
		return fmt.Errorf("gateway_ip is required")
	}
	return nil
}

func defaultGateway(cidr string) string {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return ""
	}
	ip := ipnet.IP.To4()
	if ip == nil {
		return ""
	}
	ip[3]++
	return ip.String()
}
