package qdt

import (
	"context"
	"errors"
	"fmt"
	"io"
)

type DatagramConn interface {
	SendDatagram([]byte) error
	ReceiveDatagram(context.Context) ([]byte, error)
}

var (
	ErrSessionMismatch = errors.New("session id mismatch")
	ErrPayloadTooLarge = errors.New("payload exceeds mtu")
)

type Tunnel struct {
	SessionID uint64
	MTU       int
	Send      *CipherState
	Recv      *CipherState
	Frag      *Fragmenter
	Reasm     *Reassembler

	payloadMTUValue     int
	fragPayloadMTUValue int
	scratch             []byte
	fragScratch         []byte
}

func NewTunnel(sessionID uint64, mtu int, send, recv *CipherState) *Tunnel {
	return NewTunnelWithLimits(sessionID, mtu, send, recv, 0)
}

func NewTunnelWithLimits(sessionID uint64, mtu int, send, recv *CipherState, maxReassembly int) *Tunnel {
	if mtu <= 0 {
		mtu = DefaultMTU
	}
	t := &Tunnel{
		SessionID: sessionID,
		MTU:       mtu,
		Send:      send,
		Recv:      recv,
		Frag:      &Fragmenter{},
		Reasm:     NewReassembler(0, 0, maxReassembly),
	}
	t.recomputeMTU()
	return t
}

func (t *Tunnel) recomputeMTU() {
	overhead := HeaderLen
	if t.Send != nil {
		overhead += t.Send.Overhead()
	}
	t.payloadMTUValue = t.MTU - overhead
	t.fragPayloadMTUValue = t.payloadMTUValue - fragHeaderLen
}

func (t *Tunnel) payloadMTU() int {
	return t.payloadMTUValue
}

func (t *Tunnel) fragmentPayloadMTU() int {
	return t.fragPayloadMTUValue
}

func (t *Tunnel) datagramScratch(size int) []byte {
	if cap(t.scratch) < size {
		t.scratch = make([]byte, size)
	}
	return t.scratch[:size]
}

func (t *Tunnel) fragmentScratch(size int) []byte {
	if cap(t.fragScratch) < size {
		t.fragScratch = make([]byte, size)
	}
	return t.fragScratch[:size]
}

func (t *Tunnel) EncodePacket(payload []byte, emit func([]byte) error) error {
	if t.Send == nil {
		return errors.New("send cipher not set")
	}
	maxPayload := t.payloadMTU()
	if maxPayload <= 0 {
		return fmt.Errorf("invalid mtu")
	}
	if len(payload) <= maxPayload {
		return t.encodeAndEmit(MsgData, payload, emit)
	}
	fragMax := t.fragmentPayloadMTU()
	if fragMax <= 0 {
		return fmt.Errorf("fragment mtu too small")
	}
	fragID := t.Frag.NextID()
	offset := 0
	for offset < len(payload) {
		end := offset + fragMax
		if end > len(payload) {
			end = len(payload)
		}
		plainLen := fragHeaderLen + (end - offset)
		plain := t.fragmentScratch(plainLen)
		WriteFragmentHeader(plain[:fragHeaderLen], fragID, uint32(offset), uint32(len(payload)))
		copy(plain[fragHeaderLen:], payload[offset:end])
		if err := t.encodeAndEmit(MsgFragment, plain, emit); err != nil {
			return err
		}
		offset = end
	}
	return nil
}

func (t *Tunnel) encodeAndEmit(msgType MessageType, payload []byte, emit func([]byte) error) error {
	counter := t.Send.NextCounter()
	overhead := t.Send.Overhead()
	bufSize := HeaderLen + overhead + len(payload)
	hdr := Header{
		Version:   ProtocolVersion,
		Type:      msgType,
		Flags:     0,
		SessionID: t.SessionID,
		Counter:   counter,
	}
	buf := t.datagramScratch(bufSize)
	WriteHeader(buf[:HeaderLen], hdr)
	buf = t.Send.Seal(buf[:HeaderLen], counter, buf[:HeaderLen], payload)
	return emit(buf)
}

// Encoder provides per-goroutine scratch buffers for concurrent encoding.
type Encoder struct {
	t           *Tunnel
	scratch     []byte
	fragScratch []byte
}

func (t *Tunnel) NewEncoder() *Encoder {
	return &Encoder{t: t}
}

func (e *Encoder) EncodePacket(payload []byte, emit func([]byte) error) error {
	t := e.t
	if t.Send == nil {
		return errors.New("send cipher not set")
	}
	maxPayload := t.payloadMTUValue
	if maxPayload <= 0 {
		return fmt.Errorf("invalid mtu")
	}
	if len(payload) <= maxPayload {
		return e.encodeAndEmit(MsgData, payload, emit)
	}
	fragMax := t.fragPayloadMTUValue
	if fragMax <= 0 {
		return fmt.Errorf("fragment mtu too small")
	}
	fragID := t.Frag.NextID()
	offset := 0
	for offset < len(payload) {
		end := offset + fragMax
		if end > len(payload) {
			end = len(payload)
		}
		plainLen := fragHeaderLen + (end - offset)
		plain := e.fragmentScratch(plainLen)
		WriteFragmentHeader(plain[:fragHeaderLen], fragID, uint32(offset), uint32(len(payload)))
		copy(plain[fragHeaderLen:], payload[offset:end])
		if err := e.encodeAndEmit(MsgFragment, plain, emit); err != nil {
			return err
		}
		offset = end
	}
	return nil
}

func (e *Encoder) encodeAndEmit(msgType MessageType, payload []byte, emit func([]byte) error) error {
	t := e.t
	counter := t.Send.NextCounter()
	overhead := t.Send.Overhead()
	bufSize := HeaderLen + overhead + len(payload)
	hdr := Header{
		Version:   ProtocolVersion,
		Type:      msgType,
		Flags:     0,
		SessionID: t.SessionID,
		Counter:   counter,
	}
	buf := e.datagramScratch(bufSize)
	WriteHeader(buf[:HeaderLen], hdr)
	buf = t.Send.Seal(buf[:HeaderLen], counter, buf[:HeaderLen], payload)
	return emit(buf)
}

// EncodePacketTo writes encrypted datagrams into caller-provided buffers.
func (e *Encoder) EncodePacketTo(payload []byte, alloc func(size int) []byte, emit func([]byte) error) error {
	t := e.t
	if t.Send == nil {
		return errors.New("send cipher not set")
	}
	maxPayload := t.payloadMTUValue
	if maxPayload <= 0 {
		return fmt.Errorf("invalid mtu")
	}
	if len(payload) <= maxPayload {
		return e.encodeAndEmitTo(MsgData, payload, alloc, emit)
	}
	fragMax := t.fragPayloadMTUValue
	if fragMax <= 0 {
		return fmt.Errorf("fragment mtu too small")
	}
	fragID := t.Frag.NextID()
	offset := 0
	for offset < len(payload) {
		end := offset + fragMax
		if end > len(payload) {
			end = len(payload)
		}
		plainLen := fragHeaderLen + (end - offset)
		plain := e.fragmentScratch(plainLen)
		WriteFragmentHeader(plain[:fragHeaderLen], fragID, uint32(offset), uint32(len(payload)))
		copy(plain[fragHeaderLen:], payload[offset:end])
		if err := e.encodeAndEmitTo(MsgFragment, plain, alloc, emit); err != nil {
			return err
		}
		offset = end
	}
	return nil
}

func (e *Encoder) encodeAndEmitTo(msgType MessageType, payload []byte, alloc func(size int) []byte, emit func([]byte) error) error {
	t := e.t
	counter := t.Send.NextCounter()
	overhead := t.Send.Overhead()
	bufSize := HeaderLen + overhead + len(payload)
	buf := alloc(bufSize)
	if cap(buf) < bufSize {
		return ErrPayloadTooLarge
	}
	if len(buf) < bufSize {
		buf = buf[:bufSize]
	}
	hdr := Header{
		Version:   ProtocolVersion,
		Type:      msgType,
		Flags:     0,
		SessionID: t.SessionID,
		Counter:   counter,
	}
	WriteHeader(buf[:HeaderLen], hdr)
	out := t.Send.Seal(buf[:HeaderLen], counter, buf[:HeaderLen], payload)
	return emit(out)
}

func (e *Encoder) datagramScratch(size int) []byte {
	if cap(e.scratch) < size {
		e.scratch = make([]byte, size)
	}
	return e.scratch[:size]
}

func (e *Encoder) fragmentScratch(size int) []byte {
	if cap(e.fragScratch) < size {
		e.fragScratch = make([]byte, size)
	}
	return e.fragScratch[:size]
}

func (t *Tunnel) DecodeDatagram(raw []byte) ([]byte, error) {
	pkt, _, err := t.DecodeDatagramInto(nil, raw)
	return pkt, err
}

func (t *Tunnel) DecodeDatagramInto(dst []byte, raw []byte) ([]byte, bool, error) {
	if t.Recv == nil {
		return nil, false, errors.New("recv cipher not set")
	}
	hdr, ciphertext, err := ParseHeader(raw)
	if err != nil {
		return nil, false, err
	}
	if hdr.SessionID != t.SessionID {
		return nil, false, ErrSessionMismatch
	}
	plainLen := len(ciphertext) - t.Recv.Overhead()
	if plainLen < 0 {
		return nil, false, ErrInvalidDatagram
	}
	pooled := cap(dst) >= plainLen
	if pooled {
		dst = dst[:0]
	} else {
		dst = nil
	}
	plain, err := t.Recv.Open(dst, hdr.Counter, raw[:HeaderLen], ciphertext)
	if err != nil {
		return nil, false, err
	}
	switch hdr.Type {
	case MsgData:
		return plain, pooled, nil
	case MsgFragment:
		if t.Reasm == nil {
			return nil, pooled, nil
		}
		assembled, err := t.Reasm.Push(plain)
		if err != nil || assembled == nil {
			return assembled, pooled, err
		}
		if cap(dst) >= len(assembled) {
			out := dst[:len(assembled)]
			copy(out, assembled)
			return out, true, nil
		}
		return assembled, false, nil
	case MsgPing, MsgPong:
		return nil, pooled, nil
	default:
		return nil, false, fmt.Errorf("unknown message type: %d", hdr.Type)
	}
}

func (t *Tunnel) PumpTunToConn(ctx context.Context, tun io.Reader, conn DatagramConn, maxPacket int) error {
	buf := make([]byte, maxPacket)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		n, err := tun.Read(buf)
		if err != nil {
			return fmt.Errorf("read tun: %w", err)
		}
		if n == 0 {
			continue
		}
		if err := t.EncodePacket(buf[:n], conn.SendDatagram); err != nil {
			return err
		}
	}
}

func (t *Tunnel) PumpConnToTun(ctx context.Context, tun io.Writer, conn DatagramConn) error {
	for {
		b, err := conn.ReceiveDatagram(ctx)
		if err != nil {
			return fmt.Errorf("receive datagram: %w", err)
		}
		pkt, err := t.DecodeDatagram(b)
		if err != nil {
			return err
		}
		if len(pkt) == 0 {
			continue
		}
		if _, err := tun.Write(pkt); err != nil {
			return fmt.Errorf("write tun: %w", err)
		}
	}
}

// PumpConnToTunBuffered uses a reusable buffer to reduce allocations.
func (t *Tunnel) PumpConnToTunBuffered(ctx context.Context, tun io.Writer, conn DatagramConn, maxPacket int) error {
	buf := make([]byte, maxPacket)
	for {
		b, err := conn.ReceiveDatagram(ctx)
		if err != nil {
			return fmt.Errorf("receive datagram: %w", err)
		}
		pkt, pooled, err := t.DecodeDatagramInto(buf[:0], b)
		if err != nil {
			return err
		}
		if len(pkt) == 0 {
			continue
		}
		if !pooled {
			if len(pkt) > cap(buf) {
				return fmt.Errorf("packet too large: %d", len(pkt))
			}
			copy(buf, pkt)
			pkt = buf[:len(pkt)]
		}
		if _, err := tun.Write(pkt); err != nil {
			return fmt.Errorf("write tun: %w", err)
		}
	}
}
