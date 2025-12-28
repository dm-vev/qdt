package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"

	"qdt/internal/tun"
	"qdt/pkg/qdt"
)

const maxPacketSize = 65535

type session struct {
	stream *http3.Stream
	tunnel *qdt.Tunnel
}

type server struct {
	token string
	tun   *tun.Device
	mtu   int

	mu      sync.Mutex
	current *session
}

func (s *server) connectHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if r.Header.Get(qdt.TokenHeader) != s.token {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	streamer, ok := w.(http3.HTTPStreamer)
	if !ok {
		http.Error(w, "not http3", http.StatusBadRequest)
		return
	}

	s.mu.Lock()
	if s.current != nil {
		s.mu.Unlock()
		http.Error(w, "session already active", http.StatusConflict)
		return
	}
	stream := streamer.HTTPStream()
	sessionID, err := qdt.NewSessionID()
	if err != nil {
		s.mu.Unlock()
		http.Error(w, "session id error", http.StatusInternalServerError)
		return
	}
	tunnel := qdt.NewTunnel(sessionID, s.mtu)
	s.current = &session{stream: stream, tunnel: tunnel}
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		s.current = nil
		s.mu.Unlock()
	}()

	if err := qdt.WriteConnectResponse(w, qdt.ConnectResponse{Version: qdt.ProtocolVersion, SessionID: sessionID, MTU: s.mtu}); err != nil {
		log.Printf("connect response error: %v", err)
		return
	}
	if flusher, ok := w.(http.Flusher); ok {
		flusher.Flush()
	}

	ctx := stream.Context()
	errCh := make(chan error, 2)

	go func() {
		errCh <- tunnel.PumpTunToConn(ctx, s.tun, stream, maxPacketSize)
	}()

	go func() {
		errCh <- tunnel.PumpConnToTun(ctx, s.tun, stream)
	}()

	select {
	case <-ctx.Done():
		return
	case err := <-errCh:
		log.Printf("session ended: %v", err)
		return
	}
}

func main() {
	var (
		addr    = flag.String("addr", ":443", "UDP listen address")
		cert    = flag.String("cert", "", "path to TLS cert")
		key     = flag.String("key", "", "path to TLS key")
		tok     = flag.String("token", "", "auth token")
		tunName = flag.String("tun", "qdt0", "TUN interface name")
		mtu     = flag.Int("mtu", qdt.DefaultMTU, "TUN MTU to advertise")
	)
	flag.Parse()

	if *cert == "" || *key == "" || *tok == "" {
		log.Fatal("cert, key, and token are required")
	}

	tunDev, err := tun.Open(*tunName)
	if err != nil {
		log.Fatalf("tun open: %v", err)
	}
	defer tunDev.Close()
	log.Printf("TUN device: %s", tunDev.Name)

	tlsCert, err := tls.LoadX509KeyPair(*cert, *key)
	if err != nil {
		log.Fatalf("load cert: %v", err)
	}

	tlsConf := &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		NextProtos:   []string{http3.NextProtoH3},
	}

	s := &server{token: *tok, tun: tunDev, mtu: *mtu}
	mux := http.NewServeMux()
	mux.HandleFunc("/connect", s.connectHandler)

	srv := &http3.Server{
		Addr:            *addr,
		Handler:         mux,
		TLSConfig:       tlsConf,
		EnableDatagrams: true,
		QUICConfig: &quic.Config{
			EnableDatagrams: true,
			KeepAlivePeriod: 15 * time.Second,
		},
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.ListenAndServe()
	}()

	select {
	case <-stop:
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	case err := <-errCh:
		if !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("server error: %v", err)
		}
	}
}
