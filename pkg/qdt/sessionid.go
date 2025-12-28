package qdt

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
)

func NewSessionID() (uint64, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0, fmt.Errorf("session id: %w", err)
	}
	return binary.BigEndian.Uint64(b[:]), nil
}
