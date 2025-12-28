package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"

	"qdt/internal/tun"
	"qdt/pkg/qdt"
)

const maxPacketSize = 65535

func main() {
	var (
		server   = flag.String("server", "", "server host:port")
		token    = flag.String("token", "", "auth token")
		tunName  = flag.String("tun", "qdt0", "TUN interface name")
		insecure = flag.Bool("insecure", false, "skip TLS verification (dev only)")
	)
	flag.Parse()

	if *server == "" || *token == "" {
		log.Fatal("server and token are required")
	}

	host, _, err := net.SplitHostPort(*server)
	if err != nil {
		log.Fatalf("invalid server address: %v", err)
	}

	tunDev, err := tun.Open(*tunName)
	if err != nil {
		log.Fatalf("tun open: %v", err)
	}
	defer tunDev.Close()
	log.Printf("TUN device: %s", tunDev.Name)

	tlsConf := &tls.Config{
		InsecureSkipVerify: *insecure,
		NextProtos:         []string{http3.NextProtoH3},
		ServerName:         host,
	}

	quicConf := &quic.Config{
		EnableDatagrams: true,
		KeepAlivePeriod: 15 * time.Second,
	}

	ctx := context.Background()
	conn, err := quic.DialAddr(ctx, *server, tlsConf, quicConf)
	if err != nil {
		log.Fatalf("quic dial: %v", err)
	}
	defer conn.CloseWithError(0, "")

	tr := &http3.Transport{EnableDatagrams: true}
	cc := tr.NewClientConn(conn)

	reqStream, err := cc.OpenRequestStream(ctx)
	if err != nil {
		log.Fatalf("open request stream: %v", err)
	}

	reqURL := &url.URL{Scheme: "https", Host: host, Path: qdt.ConnectPath}
	req := &http.Request{
		Method: http.MethodPost,
		URL:    reqURL,
		Header: make(http.Header),
	}
	req.Header.Set(qdt.TokenHeader, *token)

	if err := reqStream.SendRequestHeader(req); err != nil {
		log.Fatalf("send request: %v", err)
	}

	resp, err := reqStream.ReadResponse()
	if err != nil {
		log.Fatalf("read response: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		log.Fatalf("connect failed: %s (%s)", resp.Status, string(body))
	}
	connectResp, err := qdt.ReadConnectResponse(resp.Body)
	if err != nil {
		log.Fatalf("read connect response: %v", err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)

	tunnel := qdt.NewTunnel(connectResp.SessionID, connectResp.MTU)

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	loopCtx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 2)

	go func() {
		errCh <- tunnel.PumpTunToConn(loopCtx, tunDev, reqStream, maxPacketSize)
	}()

	go func() {
		errCh <- tunnel.PumpConnToTun(loopCtx, tunDev, reqStream)
	}()

	select {
	case <-stop:
		cancel()
	case err := <-errCh:
		if !errors.Is(err, context.Canceled) {
			log.Printf("session ended: %v", err)
		}
	}
}
