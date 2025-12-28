package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"qdt/internal/logging"
)

func main() {
	runtime.GOMAXPROCS(runtime.NumCPU())

	var configPath string
	flag.StringVar(&configPath, "config", "server.yaml", "path to config file")
	flag.Parse()

	cfg, err := LoadConfig(configPath)
	if err != nil {
		slog.Error("config error", "err", err)
		os.Exit(1)
	}

	logger, err := logging.New(cfg.LogLevel, cfg.LogJSON)
	if err != nil {
		slog.Error("logger error", "err", err)
		os.Exit(1)
	}

	metrics := NewMetrics()
	server, err := NewServer(cfg, logger, metrics)
	if err != nil {
		logger.Error("server init error", "err", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := server.Serve(ctx); err != nil && err != context.Canceled {
		logger.Error("server error", "err", err)
		time.Sleep(100 * time.Millisecond)
		os.Exit(1)
	}
}
