package qdt

import (
	"bytes"
	"testing"
	"time"
)

func TestReassembly(t *testing.T) {
	payload := bytes.Repeat([]byte("a"), 4000)
	frag := &Fragmenter{}
	id := frag.NextID()
	reasm := NewReassembler(2*time.Second, 10)

	chunk := 1000
	for offset := 0; offset < len(payload); offset += chunk {
		end := offset + chunk
		if end > len(payload) {
			end = len(payload)
		}
		hdr := EncodeFragmentHeader(id, uint32(offset), uint32(len(payload)))
		b := append(hdr, payload[offset:end]...)
		out, err := reasm.Push(b)
		if err != nil {
			t.Fatalf("push: %v", err)
		}
		if end == len(payload) {
			if out == nil {
				t.Fatalf("expected reassembly")
			}
			if !bytes.Equal(out, payload) {
				t.Fatalf("payload mismatch")
			}
		}
	}
}
