package qdt

import (
	"bytes"
	"testing"
)

func TestTunnelEncodeDecode(t *testing.T) {
	token := "secret"
	clientNonce := make([]byte, HandshakeNonceSize)
	serverNonce := make([]byte, HandshakeNonceSize)
	for i := range clientNonce {
		clientNonce[i] = byte(i)
		serverNonce[i] = byte(50 + i)
	}
	km, err := DeriveKeyMaterial(token, clientNonce, serverNonce)
	if err != nil {
		t.Fatalf("derive keys: %v", err)
	}
	send, _, err := NewClientCipherStates(km, NewReplayWindow(128))
	if err != nil {
		t.Fatalf("cipher states: %v", err)
	}
	_, recv, err := NewServerCipherStates(km, NewReplayWindow(128))
	if err != nil {
		t.Fatalf("cipher states: %v", err)
	}
	const sessionID = 123
	mtu := 400
	tun := NewTunnel(sessionID, mtu, send, recv)

	payload := bytes.Repeat([]byte("x"), 2000)
	var dgrams [][]byte
	err = tun.EncodePacket(payload, func(b []byte) error {
		cp := append([]byte(nil), b...)
		dgrams = append(dgrams, cp)
		return nil
	})
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	var out []byte
	for _, d := range dgrams {
		pkt, err := tun.DecodeDatagram(d)
		if err != nil {
			t.Fatalf("decode: %v", err)
		}
		if len(pkt) > 0 {
			out = pkt
		}
	}
	if !bytes.Equal(out, payload) {
		t.Fatalf("payload mismatch")
	}
}
