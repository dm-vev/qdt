package qdt

import "testing"

func TestHeaderRoundTrip(t *testing.T) {
	h := Header{Version: ProtocolVersion, Type: MsgData, Flags: 1, SessionID: 42, Counter: 7}
	buf := AppendHeader(nil, h)
	payload := []byte("test")
	buf = append(buf, payload...)

	parsed, rest, err := ParseHeader(buf)
	if err != nil {
		t.Fatalf("parse header: %v", err)
	}
	if parsed != h {
		t.Fatalf("header mismatch: %+v != %+v", parsed, h)
	}
	if string(rest) != string(payload) {
		t.Fatalf("payload mismatch")
	}
}

func TestHeaderInvalid(t *testing.T) {
	_, _, err := ParseHeader([]byte("bad"))
	if err == nil {
		t.Fatalf("expected error")
	}
	buf := AppendHeader(nil, Header{Version: 9})
	buf[0] = 'X'
	_, _, err = ParseHeader(buf)
	if err == nil {
		t.Fatalf("expected error for magic")
	}
}
