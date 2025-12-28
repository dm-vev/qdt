package qdt

import "testing"

func TestReplayWindow(t *testing.T) {
	w := NewReplayWindow(4)
	if !w.Check(1) {
		t.Fatalf("first packet should be accepted")
	}
	w.Mark(1)
	if w.Check(1) {
		t.Fatalf("duplicate should be rejected")
	}
	w.Mark(2)
	if !w.Check(3) {
		t.Fatalf("new packet should be accepted")
	}
	w.Mark(10)
	old := uint64(5)
	if w.Check(old) {
		t.Fatalf("too old packet should be rejected")
	}
}
