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

const (
	fragHeaderLen        = 12
	DefaultMaxReassembly = 65535
)

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
	maxTotal   int
	frags      map[uint32]*fragState
	lastSweep  time.Time
}

type fragState struct {
	total     int
	received  int
	updatedAt time.Time
	buf       []byte
	segments  []fragSegment
}

type fragSegment struct {
	start int
	end   int
}

func NewReassembler(ttl time.Duration, maxEntries int, maxTotal int) *Reassembler {
	if ttl <= 0 {
		ttl = 5 * time.Second
	}
	if maxEntries <= 0 {
		maxEntries = 1024
	}
	if maxTotal <= 0 {
		maxTotal = DefaultMaxReassembly
	}
	return &Reassembler{ttl: ttl, maxEntries: maxEntries, maxTotal: maxTotal, frags: make(map[uint32]*fragState)}
}

func (r *Reassembler) Push(b []byte) ([]byte, error) {
	id, offset, total, payload, err := DecodeFragmentHeader(b)
	if err != nil {
		return nil, err
	}
	if total == 0 {
		return nil, fmt.Errorf("invalid fragment total")
	}
	if r.maxTotal > 0 && int(total) > r.maxTotal {
		return nil, fmt.Errorf("fragment total too large")
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
			buf:       make([]byte, int(total)),
			segments:  make([]fragSegment, 0, 8),
		}
		r.frags[id] = state
	}
	off := int(offset)
	end := off + len(payload)
	segs := state.segments
	if n := len(segs); n > 0 {
		last := segs[n-1]
		if off >= last.end {
			copy(state.buf[off:end], payload)
			state.segments = append(segs, fragSegment{start: off, end: end})
			state.received += len(payload)
			state.updatedAt = time.Now()
			if state.received < state.total {
				return nil, nil
			}
			assembled, err := assemble(state)
			delete(r.frags, id)
			return assembled, err
		}
	}
	idx := sort.Search(len(segs), func(i int) bool {
		return segs[i].start >= off
	})
	if idx > 0 && segs[idx-1].end > off {
		delete(r.frags, id)
		return nil, ErrFragmentOverlap
	}
	if idx < len(segs) && segs[idx].start < end {
		delete(r.frags, id)
		return nil, ErrFragmentOverlap
	}
	copy(state.buf[off:end], payload)
	state.segments = append(segs, fragSegment{})
	copy(state.segments[idx+1:], segs[idx:])
	state.segments[idx] = fragSegment{start: off, end: end}
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
	pos := 0
	for _, seg := range state.segments {
		if seg.start != pos {
			return nil, fmt.Errorf("fragment gap")
		}
		pos = seg.end
	}
	if pos != state.total {
		return nil, fmt.Errorf("fragment size mismatch")
	}
	return state.buf, nil
}
