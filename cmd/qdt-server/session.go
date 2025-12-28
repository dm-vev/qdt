package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go/http3"
	"golang.org/x/time/rate"

	"qdt/internal/bufferpool"
	"qdt/internal/iputil"
	"qdt/pkg/qdt"
)

type Session struct {
	id          uint64
	ip          net.IP
	ip4         uint32
	stream      *http3.Stream
	tunnel      *qdt.Tunnel
	sendCh      chan []byte
	sendMu      *sync.Mutex
	sendWorkers int
	sendBatch   int
	closeOnce   sync.Once
	closed      chan struct{}
	lastSeen    atomic.Int64
	inLimiter   *rate.Limiter
	outLimiter  *rate.Limiter
	metrics     *Metrics
	pool        *bufferpool.Pool
	onClose     func(*Session, error)
	tunWriteCh  chan<- []byte
}

func newSession(id uint64, ip net.IP, ip4 uint32, stream *http3.Stream, tunnel *qdt.Tunnel, pool *bufferpool.Pool, tunWriteCh chan<- []byte, limiter *rate.Limiter, sendWorkers int, sendQueue int, sendBatch int, metrics *Metrics, onClose func(*Session, error)) *Session {
	if sendWorkers <= 0 {
		sendWorkers = 1
	}
	if sendQueue <= 0 {
		sendQueue = 1024
	}
	if sendBatch <= 0 {
		sendBatch = 1
	}
	var sendMu *sync.Mutex
	if sendWorkers > 1 {
		sendMu = &sync.Mutex{}
	}
	s := &Session{
		id:          id,
		ip:          ip,
		ip4:         ip4,
		stream:      stream,
		tunnel:      tunnel,
		sendCh:      make(chan []byte, sendQueue),
		sendMu:      sendMu,
		sendWorkers: sendWorkers,
		sendBatch:   sendBatch,
		closed:      make(chan struct{}),
		inLimiter:   limiter,
		outLimiter:  limiter,
		metrics:     metrics,
		pool:        pool,
		onClose:     onClose,
		tunWriteCh:  tunWriteCh,
	}
	s.lastSeen.Store(time.Now().UnixNano())
	return s
}

func (s *Session) Start(ctx context.Context) {
	go s.recvLoop(ctx)
	for i := 0; i < s.sendWorkers; i++ {
		go s.sendLoop(ctx)
	}
}

func (s *Session) Enqueue(pkt []byte) bool {
	select {
	case s.sendCh <- pkt:
		return true
	default:
		return false
	}
}

func (s *Session) Close(err error) {
	s.closeOnce.Do(func() {
		close(s.closed)
		if s.onClose != nil {
			s.onClose(s, err)
		}
	})
}

func (s *Session) recvLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			s.Close(ctx.Err())
			return
		case <-s.closed:
			return
		default:
		}
		b, err := s.stream.ReceiveDatagram(ctx)
		if err != nil {
			s.Close(fmt.Errorf("receive datagram: %w", err))
			return
		}
		if s.inLimiter != nil && !s.inLimiter.Allow() {
			s.metrics.drops.WithLabelValues("rate_in").Inc()
			continue
		}
		dst := s.pool.Get()
		pkt, pooled, err := s.tunnel.DecodeDatagramInto(dst[:0], b)
		if err != nil {
			s.pool.Put(dst)
			if errors.Is(err, qdt.ErrReplay) {
				s.metrics.drops.WithLabelValues("replay").Inc()
				continue
			}
			s.metrics.drops.WithLabelValues("decode").Inc()
			continue
		}
		if len(pkt) == 0 {
			s.pool.Put(dst)
			continue
		}
		if !pooled {
			if len(pkt) > cap(dst) {
				s.pool.Put(dst)
				s.metrics.drops.WithLabelValues("decode_oversize").Inc()
				continue
			}
			copy(dst, pkt)
			pkt = dst[:len(pkt)]
			pooled = true
		}
		src4, ok := iputil.PacketSourceV4(pkt)
		if !ok {
			s.pool.Put(dst)
			s.metrics.drops.WithLabelValues("bad_packet").Inc()
			continue
		}
		if src4 != s.ip4 {
			s.pool.Put(dst)
			s.metrics.drops.WithLabelValues("src_mismatch").Inc()
			continue
		}
		s.lastSeen.Store(time.Now().UnixNano())
		select {
		case s.tunWriteCh <- pkt:
			s.metrics.packets.WithLabelValues("in").Inc()
			s.metrics.bytes.WithLabelValues("in").Add(float64(len(pkt)))
		default:
			if pooled {
				s.pool.Put(pkt)
			} else {
				s.pool.Put(dst)
			}
			s.metrics.drops.WithLabelValues("tun_backpressure").Inc()
		case <-s.closed:
			if pooled {
				s.pool.Put(pkt)
			} else {
				s.pool.Put(dst)
			}
			return
		}
	}
}

func (s *Session) sendLoop(ctx context.Context) {
	enc := s.tunnel.NewEncoder()
	for {
		select {
		case <-ctx.Done():
			s.Close(ctx.Err())
			return
		case <-s.closed:
			return
		case pkt := <-s.sendCh:
			if err := s.processSend(enc, pkt); err != nil {
				return
			}
		batchLoop:
			for i := 1; i < s.sendBatch; i++ {
				select {
				case next := <-s.sendCh:
					if err := s.processSend(enc, next); err != nil {
						return
					}
				default:
					break batchLoop
				}
			}
		}
	}
}

func (s *Session) processSend(enc *qdt.Encoder, pkt []byte) error {
	if s.outLimiter != nil && !s.outLimiter.Allow() {
		s.metrics.drops.WithLabelValues("rate_out").Inc()
		s.pool.Put(pkt)
		return nil
	}
	if err := enc.EncodePacket(pkt, s.sendDatagram); err != nil {
		s.pool.Put(pkt)
		s.Close(fmt.Errorf("send datagram: %w", err))
		return err
	}
	s.metrics.packets.WithLabelValues("out").Inc()
	s.metrics.bytes.WithLabelValues("out").Add(float64(len(pkt)))
	s.lastSeen.Store(time.Now().UnixNano())
	s.pool.Put(pkt)
	return nil
}

func (s *Session) sendDatagram(b []byte) error {
	if s.sendMu == nil {
		return s.stream.SendDatagram(b)
	}
	s.sendMu.Lock()
	defer s.sendMu.Unlock()
	return s.stream.SendDatagram(b)
}
