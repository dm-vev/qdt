package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"syscall"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"

	"qdt/internal/logging"
	"qdt/internal/netcfg"
	"qdt/internal/tun"
	"qdt/pkg/qdt"
)

const maxPacketSize = 65535

func main() {
	runtime.GOMAXPROCS(runtime.NumCPU())

	var configPath string
	flag.StringVar(&configPath, "config", "client.yaml", "path to config file")
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

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := run(ctx, cfg, logger); err != nil && err != context.Canceled {
		logger.Error("client error", "err", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, cfg Config, log *slog.Logger) error {
	tunDev, err := tun.Open(cfg.TunName)
	if err != nil {
		return fmt.Errorf("tun open: %w", err)
	}
	defer tunDev.Close()

	host, _, err := net.SplitHostPort(cfg.Server)
	if err != nil {
		return fmt.Errorf("invalid server address: %w", err)
	}

	tlsConf := &tls.Config{
		InsecureSkipVerify: cfg.Insecure,
		NextProtos:         []string{http3.NextProtoH3},
		ServerName:         host,
	}

	quicConf := &quic.Config{
		EnableDatagrams: true,
		KeepAlivePeriod: 10 * time.Second,
		MaxIdleTimeout:  30 * time.Second,
	}

	dialCtx, cancel := context.WithTimeout(ctx, cfg.Timeout)
	defer cancel()
	conn, err := quic.DialAddr(dialCtx, cfg.Server, tlsConf, quicConf)
	if err != nil {
		return fmt.Errorf("quic dial: %w", err)
	}
	defer conn.CloseWithError(0, "")

	tr := &http3.Transport{EnableDatagrams: true}
	cc := tr.NewClientConn(conn)
	stream, err := cc.OpenRequestStream(ctx)
	if err != nil {
		return fmt.Errorf("open request stream: %w", err)
	}

	clientNonce, err := qdt.NewHandshakeNonce()
	if err != nil {
		return fmt.Errorf("nonce: %w", err)
	}
	caps := []string{"fragment", "aead"}
	req := qdt.NewConnectRequest(clientNonce, cfg.MTU, caps, cfg.ClientID, runtime.GOOS)
	payload, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("encode connect request: %w", err)
	}

	reqURL := &url.URL{Scheme: "https", Host: host, Path: qdt.ConnectPath}
	hdr := make(http.Header)
	hdr.Set(qdt.TokenHeader, cfg.Token)
	hdr.Set("Content-Type", "application/json")
	hdr.Set("Content-Length", strconv.Itoa(len(payload)))

	hreq := &http.Request{Method: http.MethodPost, URL: reqURL, Header: hdr}
	if err := stream.SendRequestHeader(hreq); err != nil {
		return fmt.Errorf("send request: %w", err)
	}
	if _, err := stream.Write(payload); err != nil {
		return fmt.Errorf("write request body: %w", err)
	}

	resp, err := stream.ReadResponse()
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("connect failed: %s (%s)", resp.Status, string(body))
	}
	connectResp, err := qdt.ReadConnectResponse(resp.Body)
	if err != nil {
		return fmt.Errorf("read connect response: %w", err)
	}

	serverNonce, err := qdt.DecodeNonce(connectResp.ServerNonce)
	if err != nil {
		return fmt.Errorf("decode server nonce: %w", err)
	}
	keys, err := qdt.DeriveKeyMaterial(cfg.Token, clientNonce, serverNonce)
	if err != nil {
		return fmt.Errorf("key derivation: %w", err)
	}
	replay := qdt.NewReplayWindow(2048)
	send, recv, err := qdt.NewClientCipherStates(keys, replay)
	if err != nil {
		return fmt.Errorf("cipher: %w", err)
	}
	mtu := connectResp.MTU
	if mtu <= 0 {
		mtu = cfg.MTU
	}
	tunnel := qdt.NewTunnel(connectResp.SessionID, mtu, send, recv)

	routes, err := configureClientInterface(tunDev.Name, connectResp, cfg, log)
	if err != nil {
		return err
	}
	defer func() {
		if err := netcfg.DeleteRoutes(tunDev.Name, routes); err != nil {
			log.Warn("route cleanup failed", "err", err)
		}
	}()

	loopCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	errCh := make(chan error, 2)
	go func() {
		errCh <- tunnel.PumpTunToConn(loopCtx, tunDev, stream, maxPacketSize)
	}()
	go func() {
		errCh <- tunnel.PumpConnToTunBuffered(loopCtx, tunDev, stream, maxPacketSize)
	}()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-errCh:
		return err
	}
}

func configureClientInterface(ifName string, resp qdt.ConnectResponse, cfg Config, log *slog.Logger) ([]netcfg.Route, error) {
	addr, err := clientAddress(resp.ClientIP, resp.CIDR)
	if err != nil {
		return nil, err
	}
	if err := netcfg.ConfigureInterface(netcfg.InterfaceConfig{
		Name:    ifName,
		Address: addr,
		Gateway: resp.GatewayIP,
		MTU:     resp.MTU,
	}); err != nil {
		return nil, fmt.Errorf("configure tun: %w", err)
	}

	routes := buildRoutes(cfg.RouteMode, resp)
	if err := netcfg.AddRoutes(ifName, routes); err != nil {
		return nil, fmt.Errorf("add routes: %w", err)
	}

	dns := cfg.DNS
	if len(dns) == 0 {
		dns = resp.DNS
	}
	if err := netcfg.SetDNS(ifName, dns); err != nil {
		log.Warn("set dns failed", "err", err)
	}

	return routes, nil
}

func buildRoutes(mode string, resp qdt.ConnectResponse) []netcfg.Route {
	switch mode {
	case "none":
		return nil
	case "cidr":
		return []netcfg.Route{{Dest: resp.CIDR, Gateway: resp.GatewayIP}}
	default:
		return []netcfg.Route{{Dest: "0.0.0.0/0", Gateway: resp.GatewayIP}}
	}
}

func clientAddress(clientIP, cidr string) (string, error) {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return "", fmt.Errorf("parse cidr: %w", err)
	}
	maskSize, _ := ipnet.Mask.Size()
	return fmt.Sprintf("%s/%d", clientIP, maskSize), nil
}
