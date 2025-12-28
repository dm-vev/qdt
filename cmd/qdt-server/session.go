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
	dgCh        chan []byte
	dgPool      *bufferpool.Pool
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

func newSession(id uint64, ip net.IP, ip4 uint32, stream *http3.Stream, tunnel *qdt.Tunnel, pool *bufferpool.Pool, dgPool *bufferpool.Pool, tunWriteCh chan<- []byte, limiter *rate.Limiter, sendWorkers int, sendQueue int, dgQueue int, sendBatch int, metrics *Metrics, onClose func(*Session, error)) *Session {
	if sendWorkers <= 0 {
		sendWorkers = 1
	}
	if sendQueue <= 0 {
		sendQueue = 1024
	}
	if dgQueue <= 0 {
		dgQueue = sendQueue
	}
	if sendBatch <= 0 {
		sendBatch = 1
	}
	s := &Session{
		id:          id,
		ip:          ip,
		ip4:         ip4,
		stream:      stream,
		tunnel:      tunnel,
		sendCh:      make(chan []byte, sendQueue),
		dgCh:        make(chan []byte, dgQueue),
		dgPool:      dgPool,
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
	go s.sendLoop(ctx)
	for i := 0; i < s.sendWorkers; i++ {
		go s.encodeLoop(ctx)
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

func (s *Session) encodeLoop(ctx context.Context) {
	enc := s.tunnel.NewEncoder()
	for {
		select {
		case <-ctx.Done():
			s.Close(ctx.Err())
			return
		case <-s.closed:
			return
		case pkt := <-s.sendCh:
			if err := s.processEncode(enc, pkt); err != nil {
				return
			}
		batchLoop:
			for i := 1; i < s.sendBatch; i++ {
				select {
				case next := <-s.sendCh:
					if err := s.processEncode(enc, next); err != nil {
						return
					}
				default:
					break batchLoop
				}
			}
		}
	}
}

func (s *Session) processEncode(enc *qdt.Encoder, pkt []byte) error {
	if s.outLimiter != nil && !s.outLimiter.Allow() {
		s.metrics.drops.WithLabelValues("rate_out").Inc()
		s.pool.Put(pkt)
		return nil
	}
	if err := enc.EncodePacketTo(pkt, s.allocDatagram, s.enqueueDatagram); err != nil {
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

func (s *Session) allocDatagram(size int) []byte {
	buf := s.dgPool.Get()
	if size > cap(buf) {
		s.dgPool.Put(buf)
		s.metrics.drops.WithLabelValues("datagram_oversize").Inc()
		return nil
	}
	return buf[:size]
}

func (s *Session) enqueueDatagram(buf []byte) error {
	select {
	case s.dgCh <- buf:
		return nil
	case <-s.closed:
		if buf != nil {
			s.dgPool.Put(buf)
		}
		return fmt.Errorf("session closed")
	}
}

func (s *Session) sendLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			s.Close(ctx.Err())
			return
		case <-s.closed:
			return
		case dg := <-s.dgCh:
			if err := s.sendDatagram(dg); err != nil {
				return
			}
		batchLoop:
			for i := 1; i < s.sendBatch; i++ {
				select {
				case next := <-s.dgCh:
					if err := s.sendDatagram(next); err != nil {
						return
					}
				default:
					break batchLoop
				}
			}
		}
	}
}

func (s *Session) sendDatagram(dg []byte) error {
	if err := s.stream.SendDatagram(dg); err != nil {
		if dg != nil {
			s.dgPool.Put(dg)
		}
		s.Close(fmt.Errorf("send datagram: %w", err))
		return err
	}
	if dg != nil {
		s.dgPool.Put(dg)
	}
	return nil
}
