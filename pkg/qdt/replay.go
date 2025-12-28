package qdt

import "sync"

type ReplayWindow struct {
	mu          sync.Mutex
	size        uint64
	max         uint64
	initialized bool
	bits        []uint64
}

func NewReplayWindow(size uint64) *ReplayWindow {
	if size == 0 {
		size = 1024
	}
	words := (size + 63) / 64
	return &ReplayWindow{size: size, bits: make([]uint64, words)}
}

func (w *ReplayWindow) Check(counter uint64) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.initialized {
		return true
	}
	if counter+w.size <= w.max {
		return false
	}
	if counter > w.max {
		return true
	}
	offset := w.max - counter
	return !w.isSet(offset)
}

func (w *ReplayWindow) Mark(counter uint64) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.initialized {
		w.max = counter
		w.initialized = true
		w.set(0)
		return
	}
	if counter > w.max {
		delta := counter - w.max
		w.shift(delta)
		w.max = counter
		w.set(0)
		return
	}
	offset := w.max - counter
	if offset < w.size {
		w.set(offset)
	}
}

func (w *ReplayWindow) set(offset uint64) {
	idx := offset / 64
	bit := offset % 64
	w.bits[idx] |= 1 << bit
}

func (w *ReplayWindow) isSet(offset uint64) bool {
	idx := offset / 64
	bit := offset % 64
	return (w.bits[idx] & (1 << bit)) != 0
}

func (w *ReplayWindow) shift(delta uint64) {
	if delta >= w.size {
		for i := range w.bits {
			w.bits[i] = 0
		}
		return
	}
	wordShift := delta / 64
	bitShift := delta % 64
	if wordShift > 0 {
		for i := len(w.bits) - 1; i >= 0; i-- {
			var v uint64
			if i-int(wordShift) >= 0 {
				v = w.bits[i-int(wordShift)]
			}
			w.bits[i] = v
		}
	}
	if bitShift > 0 {
		for i := len(w.bits) - 1; i >= 0; i-- {
			var hi uint64
			if i > 0 {
				hi = w.bits[i-1] >> (64 - bitShift)
			}
			w.bits[i] = (w.bits[i] << bitShift) | hi
		}
	}
	maskBits := w.size % 64
	if maskBits != 0 {
		w.bits[len(w.bits)-1] &= (uint64(1) << maskBits) - 1
	}
}
