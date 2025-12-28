package qdt

import (
	"bytes"
	"testing"
)

func TestAEADRoundTrip(t *testing.T) {
	token := "secret"
	clientNonce := make([]byte, HandshakeNonceSize)
	serverNonce := make([]byte, HandshakeNonceSize)
	for i := range clientNonce {
		clientNonce[i] = byte(i)
		serverNonce[i] = byte(100 + i)
	}
	km, err := DeriveKeyMaterial(token, clientNonce, serverNonce)
	if err != nil {
		t.Fatalf("derive keys: %v", err)
	}
	replay := NewReplayWindow(128)
	send, _, err := NewClientCipherStates(km, replay)
	if err != nil {
		t.Fatalf("cipher states: %v", err)
	}
	_, recv, err := NewServerCipherStates(km, replay)
	if err != nil {
		t.Fatalf("cipher states: %v", err)
	}

	header := []byte("header")
	payload := []byte("payload")
	counter := send.NextCounter()
	ciphertext := send.Seal(nil, counter, header, payload)

	plain, err := recv.Open(nil, counter, header, ciphertext)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if !bytes.Equal(plain, payload) {
		t.Fatalf("payload mismatch")
	}
}
