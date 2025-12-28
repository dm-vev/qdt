package main

import "sync"

type sessionTable struct {
	shards []sessionShard
}

type sessionShard struct {
	mu   sync.RWMutex
	byIP map[uint32]*Session
}

func newSessionTable(shards int) *sessionTable {
	if shards <= 0 {
		shards = 64
	}
	t := &sessionTable{shards: make([]sessionShard, shards)}
	for i := range t.shards {
		t.shards[i].byIP = make(map[uint32]*Session)
	}
	return t
}

func (t *sessionTable) shard(ip uint32) *sessionShard {
	idx := int(ip % uint32(len(t.shards)))
	return &t.shards[idx]
}

func (t *sessionTable) Add(sess *Session) {
	sh := t.shard(sess.ip4)
	sh.mu.Lock()
	sh.byIP[sess.ip4] = sess
	sh.mu.Unlock()
}

func (t *sessionTable) Remove(sess *Session) {
	sh := t.shard(sess.ip4)
	sh.mu.Lock()
	delete(sh.byIP, sess.ip4)
	sh.mu.Unlock()
}

func (t *sessionTable) GetByIP(ip uint32) *Session {
	sh := t.shard(ip)
	sh.mu.RLock()
	sess := sh.byIP[ip]
	sh.mu.RUnlock()
	return sess
}

func (t *sessionTable) Snapshot() []*Session {
	var out []*Session
	for i := range t.shards {
		sh := &t.shards[i]
		sh.mu.RLock()
		for _, sess := range sh.byIP {
			out = append(out, sess)
		}
		sh.mu.RUnlock()
	}
	return out
}
