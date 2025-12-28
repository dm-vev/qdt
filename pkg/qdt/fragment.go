package qdt

import (
	"encoding/binary"
	"errors"
	"fmt"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

const fragHeaderLen = 12

var (
	ErrFragmentTooSmall = errors.New("fragment payload too small")
	ErrFragmentOverlap  = errors.New("fragment overlap")
)

type Fragmenter struct {
	nextID uint32
}

func (f *Fragmenter) NextID() uint32 {
	return atomic.AddUint32(&f.nextID, 1)
}

func EncodeFragmentHeader(id uint32, offset uint32, total uint32) []byte {
	buf := make([]byte, fragHeaderLen)
	WriteFragmentHeader(buf, id, offset, total)
	return buf
}

func WriteFragmentHeader(dst []byte, id uint32, offset uint32, total uint32) {
	if len(dst) < fragHeaderLen {
		return
	}
	binary.BigEndian.PutUint32(dst[0:4], id)
	binary.BigEndian.PutUint32(dst[4:8], offset)
	binary.BigEndian.PutUint32(dst[8:12], total)
}

func DecodeFragmentHeader(b []byte) (id uint32, offset uint32, total uint32, payload []byte, err error) {
	if len(b) < fragHeaderLen {
		return 0, 0, 0, nil, ErrFragmentTooSmall
	}
	id = binary.BigEndian.Uint32(b[0:4])
	offset = binary.BigEndian.Uint32(b[4:8])
	total = binary.BigEndian.Uint32(b[8:12])
	payload = b[fragHeaderLen:]
	return id, offset, total, payload, nil
}

type Reassembler struct {
	mu         sync.Mutex
	ttl        time.Duration
	maxEntries int
	frags      map[uint32]*fragState
	lastSweep  time.Time
}

type fragState struct {
	total     int
	received  int
	updatedAt time.Time
	parts     map[uint32][]byte
}

func NewReassembler(ttl time.Duration, maxEntries int) *Reassembler {
	if ttl <= 0 {
		ttl = 5 * time.Second
	}
	if maxEntries <= 0 {
		maxEntries = 1024
	}
	return &Reassembler{ttl: ttl, maxEntries: maxEntries, frags: make(map[uint32]*fragState)}
}

func (r *Reassembler) Push(b []byte) ([]byte, error) {
	id, offset, total, payload, err := DecodeFragmentHeader(b)
	if err != nil {
		return nil, err
	}
	if total == 0 {
		return nil, fmt.Errorf("invalid fragment total")
	}
	if int(offset)+len(payload) > int(total) {
		return nil, fmt.Errorf("fragment exceeds total")
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.frags) >= r.maxEntries {
		r.sweepLocked()
	}
	state := r.frags[id]
	if state == nil {
		state = &fragState{
			total:     int(total),
			updatedAt: time.Now(),
			parts:     make(map[uint32][]byte),
		}
		r.frags[id] = state
	}
	if _, exists := state.parts[offset]; exists {
		return nil, nil
	}
	for off, part := range state.parts {
		end := int(off) + len(part)
		if int(offset) < end && int(offset)+len(payload) > int(off) {
			delete(r.frags, id)
			return nil, ErrFragmentOverlap
		}
	}
	cp := make([]byte, len(payload))
	copy(cp, payload)
	state.parts[offset] = cp
	state.received += len(payload)
	state.updatedAt = time.Now()
	if state.received < state.total {
		return nil, nil
	}
	assembled, err := assemble(state)
	delete(r.frags, id)
	return assembled, err
}

func (r *Reassembler) sweepLocked() {
	now := time.Now()
	if now.Sub(r.lastSweep) < r.ttl {
		return
	}
	for id, state := range r.frags {
		if now.Sub(state.updatedAt) > r.ttl {
			delete(r.frags, id)
		}
	}
	r.lastSweep = now
}

func assemble(state *fragState) ([]byte, error) {
	if state.received != state.total {
		return nil, fmt.Errorf("incomplete reassembly")
	}
	offsets := make([]int, 0, len(state.parts))
	for off := range state.parts {
		offsets = append(offsets, int(off))
	}
	sort.Ints(offsets)
	buf := make([]byte, state.total)
	pos := 0
	for _, off := range offsets {
		part := state.parts[uint32(off)]
		if off != pos {
			return nil, fmt.Errorf("fragment gap")
		}
		copy(buf[off:], part)
		pos += len(part)
	}
	if pos != state.total {
		return nil, fmt.Errorf("fragment size mismatch")
	}
	return buf, nil
}
