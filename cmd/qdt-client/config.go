package main

import (
	"fmt"
	"time"

	"qdt/internal/config"
	"qdt/pkg/qdt"
)

type Config struct {
	Server             string        `yaml:"server"`
	Token              string        `yaml:"token"`
	MTU                int           `yaml:"mtu"`
	TunName            string        `yaml:"tun_name"`
	RouteMode          string        `yaml:"route_mode"`
	DNS                []string      `yaml:"dns"`
	LogLevel           string        `yaml:"log_level"`
	LogJSON            bool          `yaml:"log_json"`
	Insecure           bool          `yaml:"insecure"`
	Timeout            time.Duration `yaml:"timeout"`
	ClientID           string        `yaml:"client_id"`
	MaxReassemblyBytes int           `yaml:"max_reassembly_bytes"`
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
	if cfg.MTU == 0 {
		cfg.MTU = qdt.DefaultMTU
	}
	if cfg.TunName == "" {
		cfg.TunName = "qdt0"
	}
	if cfg.RouteMode == "" {
		cfg.RouteMode = "default"
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 10 * time.Second
	}
	if cfg.MaxReassemblyBytes == 0 {
		cfg.MaxReassemblyBytes = qdt.DefaultMaxReassembly
	}
}

func validateConfig(cfg Config) error {
	if cfg.Server == "" {
		return fmt.Errorf("server is required")
	}
	if cfg.Token == "" {
		return fmt.Errorf("token is required")
	}
	return nil
}
