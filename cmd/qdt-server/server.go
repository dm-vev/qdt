package main

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/pprof"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"golang.org/x/time/rate"

	"qdt/internal/bufferpool"
	"qdt/internal/ipam"
	"qdt/internal/iputil"
	"qdt/internal/netcfg"
	"qdt/internal/tun"
	"qdt/pkg/qdt"
)

const maxPacketSize = 65535

type Server struct {
	cfg        Config
	log        *slog.Logger
	metrics    *Metrics
	tun        *tun.Device
	pool       *ipam.Pool
	packetPool *bufferpool.Pool
	tunWriteCh chan []byte

	sessions *sessionTable
	hsLimit  *handshakeLimiter

	ready          atomic.Bool
	activeSessions atomic.Int64
}

func NewServer(cfg Config, log *slog.Logger, metrics *Metrics) (*Server, error) {
	tunDev, err := tun.Open(cfg.TunName)
	if err != nil {
		return nil, fmt.Errorf("tun open: %w", err)
	}

	gatewayIP := net.ParseIP(cfg.GatewayIP)
	if gatewayIP == nil {
		return nil, fmt.Errorf("invalid gateway ip")
	}
	pool, err := ipam.New(cfg.PoolCIDR, []net.IP{gatewayIP})
	if err != nil {
		return nil, fmt.Errorf("ip pool: %w", err)
	}

	s := &Server{
		cfg:        cfg,
		log:        log,
		metrics:    metrics,
		tun:        tunDev,
		pool:       pool,
		packetPool: bufferpool.New(maxPacketSize),
		tunWriteCh: make(chan []byte, 4096),
		sessions:   newSessionTable(cfg.SessionShards),
		hsLimit:    newHandshakeLimiter(cfg.HandshakeRate.PPS, cfg.HandshakeRate.Burst, cfg.HandshakeIPRate.PPS, cfg.HandshakeIPRate.Burst, cfg.HandshakeIPRate.TTL),
	}
	return s, nil
}

func (s *Server) Serve(ctx context.Context) error {
	if err := s.configureNetwork(); err != nil {
		return err
	}
	s.ready.Store(true)
	if s.cfg.NAT.Enabled {
		defer func() {
			if err := netcfg.CleanupNAT(s.cfg.PoolCIDR, s.cfg.NAT.ExternalIface); err != nil {
				s.log.Warn("nat cleanup failed", "err", err)
			}
		}()
	}

	tlsCert, err := tls.LoadX509KeyPair(s.cfg.TLSCert, s.cfg.TLSKey)
	if err != nil {
		return fmt.Errorf("load cert: %w", err)
	}

	tlsConf := &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		NextProtos:   []string{http3.NextProtoH3},
	}

	mux := http.NewServeMux()
	mux.HandleFunc(qdt.ConnectPath, s.connectHandler)

	h3srv := &http3.Server{
		Addr:            s.cfg.Addr,
		Handler:         mux,
		TLSConfig:       tlsConf,
		EnableDatagrams: true,
		QUICConfig: &quic.Config{
			EnableDatagrams:       true,
			KeepAlivePeriod:       10 * time.Second,
			MaxIdleTimeout:        30 * time.Second,
			MaxIncomingStreams:    32,
			MaxIncomingUniStreams: 32,
		},
	}

	metricsSrv, healthSrv := s.startMetricsServer()
	pprofSrv := s.startPprofServer()

	go s.tunWriteLoop(ctx)
	go s.tunReadLoop(ctx)
	go s.sessionSweepLoop(ctx)

	errCh := make(chan error, 1)
	go func() {
		errCh <- h3srv.ListenAndServe()
	}()

	select {
	case <-ctx.Done():
		_ = h3srv.Close()
		if metricsSrv != nil {
			_ = metricsSrv.Close()
		}
		if healthSrv != nil {
			_ = healthSrv.Close()
		}
		if pprofSrv != nil {
			_ = pprofSrv.Close()
		}
		return ctx.Err()
	case err := <-errCh:
		if !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		return nil
	}
}

func (s *Server) configureNetwork() error {
	_, ipnet, err := net.ParseCIDR(s.cfg.PoolCIDR)
	if err != nil {
		return fmt.Errorf("parse pool cidr: %w", err)
	}
	maskSize, _ := ipnet.Mask.Size()
	addr := fmt.Sprintf("%s/%d", s.cfg.GatewayIP, maskSize)
	if err := netcfg.ConfigureInterface(netcfg.InterfaceConfig{
		Name:    s.tun.Name,
		Address: addr,
		MTU:     s.cfg.MTU,
	}); err != nil {
		return fmt.Errorf("configure tun: %w", err)
	}
	if err := netcfg.EnableIPForwarding(); err != nil {
		s.log.Warn("enable ip forwarding failed", "err", err)
	}
	if s.cfg.NAT.Enabled {
		if err := netcfg.SetupNAT(s.cfg.PoolCIDR, s.cfg.NAT.ExternalIface); err != nil {
			return fmt.Errorf("nat setup: %w", err)
		}
	}
	return nil
}

func (s *Server) startMetricsServer() (*http.Server, *http.Server) {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())
	mux.HandleFunc("/healthz", s.healthHandler)

	metricsSrv := &http.Server{Addr: s.cfg.MetricsAddr, Handler: mux}
	go func() {
		if err := metricsSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			s.log.Error("metrics server error", "err", err)
		}
	}()
	if s.cfg.HealthAddr == "" || s.cfg.HealthAddr == s.cfg.MetricsAddr {
		return metricsSrv, nil
	}
	healthMux := http.NewServeMux()
	healthMux.HandleFunc("/healthz", s.healthHandler)
	healthSrv := &http.Server{Addr: s.cfg.HealthAddr, Handler: healthMux}
	go func() {
		if err := healthSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			s.log.Error("health server error", "err", err)
		}
	}()
	return metricsSrv, healthSrv
}

func (s *Server) startPprofServer() *http.Server {
	if s.cfg.PprofAddr == "" {
		return nil
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/debug/pprof/", pprof.Index)
	mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
	mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	mux.HandleFunc("/debug/pprof/trace", pprof.Trace)
	srv := &http.Server{Addr: s.cfg.PprofAddr, Handler: mux}
	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			s.log.Error("pprof server error", "err", err)
		}
	}()
	return srv
}

func (s *Server) healthHandler(w http.ResponseWriter, _ *http.Request) {
	if s.ready.Load() {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
		return
	}
	w.WriteHeader(http.StatusServiceUnavailable)
}

func (s *Server) connectHandler(w http.ResponseWriter, r *http.Request) {
	if !s.ready.Load() {
		http.Error(w, "not ready", http.StatusServiceUnavailable)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if r.Header.Get(qdt.TokenHeader) != s.cfg.Token {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	clientAddr, _ := r.Context().Value(http3.RemoteAddrContextKey).(net.Addr)
	if clientAddr != nil {
		if !s.hsLimit.Allow(remoteIP(clientAddr.String())) {
			http.Error(w, "rate limited", http.StatusTooManyRequests)
			return
		}
	} else if !s.hsLimit.Allow(remoteIP(r.RemoteAddr)) {
		http.Error(w, "rate limited", http.StatusTooManyRequests)
		return
	}
	if s.cfg.MaxSessions > 0 && s.activeSessions.Load() >= int64(s.cfg.MaxSessions) {
		http.Error(w, "server busy", http.StatusServiceUnavailable)
		return
	}
	streamer, ok := w.(http3.HTTPStreamer)
	if !ok {
		http.Error(w, "not http3", http.StatusBadRequest)
		return
	}
	req, err := qdt.DecodeConnectRequest(r.Body)
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	clientNonce, err := qdt.DecodeNonce(req.ClientNonce)
	if err != nil {
		http.Error(w, "bad nonce", http.StatusBadRequest)
		return
	}
	serverNonce, err := qdt.NewHandshakeNonce()
	if err != nil {
		http.Error(w, "nonce error", http.StatusInternalServerError)
		return
	}
	sessionID, err := qdt.NewSessionID()
	if err != nil {
		http.Error(w, "session id error", http.StatusInternalServerError)
		return
	}
	clientIP, err := s.pool.Acquire()
	if err != nil {
		http.Error(w, "address pool exhausted", http.StatusServiceUnavailable)
		return
	}
	releaseIP := true
	defer func() {
		if releaseIP {
			s.pool.Release(clientIP)
		}
	}()
	ip4 := clientIP.To4()
	if ip4 == nil {
		http.Error(w, "invalid client ip", http.StatusInternalServerError)
		return
	}
	mtu := s.cfg.MTU
	if req.MTU > 0 && req.MTU < mtu {
		mtu = req.MTU
	}
	keys, err := qdt.DeriveKeyMaterial(s.cfg.Token, clientNonce, serverNonce)
	if err != nil {
		http.Error(w, "key derivation error", http.StatusInternalServerError)
		return
	}
	replay := qdt.NewReplayWindow(2048)
	send, recv, err := qdt.NewServerCipherStates(keys, replay)
	if err != nil {
		http.Error(w, "cipher error", http.StatusInternalServerError)
		return
	}
	stream := streamer.HTTPStream()
	tunnel := qdt.NewTunnelWithLimits(sessionID, mtu, send, recv, s.cfg.MaxReassemblyBytes)

	var limiter *rate.Limiter
	if s.cfg.RateLimit.PPS > 0 && s.cfg.RateLimit.Burst > 0 {
		limiter = rate.NewLimiter(rate.Limit(s.cfg.RateLimit.PPS), s.cfg.RateLimit.Burst)
	}
	sess := newSession(sessionID, clientIP, binary.BigEndian.Uint32(ip4), stream, tunnel, s.packetPool, s.tunWriteCh, limiter, s.cfg.SendWorkers, s.cfg.SendQueue, s.cfg.SendBatch, s.metrics, s.onSessionClose)
	s.addSession(sess)
	releaseIP = false

	resp := qdt.ConnectResponse{
		Version:     qdt.ProtocolVersion,
		SessionID:   sessionID,
		ServerNonce: qdt.EncodeNonce(serverNonce),
		MTU:         mtu,
		ClientIP:    clientIP.String(),
		GatewayIP:   s.cfg.GatewayIP,
		CIDR:        s.pool.CIDR(),
		DNS:         s.cfg.DNS,
	}
	if err := qdt.WriteConnectResponse(w, resp); err != nil {
		s.log.Error("connect response failed", "err", err)
		sess.Close(err)
		return
	}
	if flusher, ok := w.(http.Flusher); ok {
		flusher.Flush()
	}
	ctx := stream.Context()
	sess.Start(ctx)
	<-sess.closed
}

func (s *Server) addSession(sess *Session) {
	s.sessions.Add(sess)
	s.metrics.sessions.Inc()
	s.activeSessions.Add(1)
}

func (s *Server) onSessionClose(sess *Session, err error) {
	if err != nil {
		s.log.Info("session closed", "id", sess.id, "ip", sess.ip.String(), "err", err)
	}
	s.sessions.Remove(sess)
	s.pool.Release(sess.ip)
	s.metrics.sessions.Dec()
	s.activeSessions.Add(-1)
}

func (s *Server) tunReadLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		pkt := s.packetPool.Get()
		n, err := s.tun.Read(pkt)
		if err != nil {
			s.packetPool.Put(pkt)
			s.log.Error("tun read error", "err", err)
			return
		}
		if n == 0 {
			s.packetPool.Put(pkt)
			continue
		}
		pkt = pkt[:n]
		dst4, ok := iputil.PacketDestV4(pkt)
		if !ok {
			s.packetPool.Put(pkt)
			s.metrics.drops.WithLabelValues("bad_packet").Inc()
			continue
		}
		sess := s.sessions.GetByIP(dst4)
		if sess == nil {
			s.packetPool.Put(pkt)
			s.metrics.drops.WithLabelValues("no_session").Inc()
			continue
		}
		if ok := sess.Enqueue(pkt); !ok {
			s.metrics.drops.WithLabelValues("queue_full").Inc()
			s.packetPool.Put(pkt)
		}
	}
}

func (s *Server) tunWriteLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case pkt := <-s.tunWriteCh:
			if _, err := s.tun.Write(pkt); err != nil {
				s.log.Error("tun write error", "err", err)
			}
			s.packetPool.Put(pkt)
		}
	}
}

func (s *Server) sessionSweepLoop(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			now := time.Now()
			list := s.sessions.Snapshot()
			for _, sess := range list {
				last := time.Unix(0, sess.lastSeen.Load())
				if now.Sub(last) > s.cfg.SessionTimeout {
					sess.Close(fmt.Errorf("idle timeout"))
				}
			}
		}
	}
}
