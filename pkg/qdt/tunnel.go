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

type Tunnel struct {
	SessionID uint64
	MTU       int
	counter   uint32
}

func NewTunnel(sessionID uint64, mtu int) *Tunnel {
	if mtu <= 0 {
		mtu = DefaultMTU
	}
	return &Tunnel{SessionID: sessionID, MTU: mtu}
}

func (t *Tunnel) Encode(payload []byte) ([]byte, error) {
	if len(payload) > t.MTU {
		return nil, fmt.Errorf("payload exceeds MTU: %d > %d", len(payload), t.MTU)
	}
	d := NewDataDatagram(t.SessionID, t.counter, payload)
	buf, err := AppendDatagram(nil, d)
	if err != nil {
		return nil, err
	}
	t.counter++
	return buf, nil
}

func (t *Tunnel) Decode(raw []byte) (Datagram, error) {
	d, err := ParseDatagram(raw)
	if err != nil {
		return Datagram{}, err
	}
	if d.SessionID != t.SessionID {
		return Datagram{}, errors.New("session id mismatch")
	}
	return d, nil
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
		encoded, err := t.Encode(buf[:n])
		if err != nil {
			return err
		}
		if err := conn.SendDatagram(encoded); err != nil {
			return fmt.Errorf("send datagram: %w", err)
		}
	}
}

func (t *Tunnel) PumpConnToTun(ctx context.Context, tun io.Writer, conn DatagramConn) error {
	for {
		b, err := conn.ReceiveDatagram(ctx)
		if err != nil {
			return fmt.Errorf("receive datagram: %w", err)
		}
		d, err := t.Decode(b)
		if err != nil {
			return err
		}
		if d.Type != MsgData {
			continue
		}
		if _, err := tun.Write(d.Payload); err != nil {
			return fmt.Errorf("write tun: %w", err)
		}
	}
}
