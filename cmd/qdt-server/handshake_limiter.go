package main

import (
	"net"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

type handshakeLimiter struct {
	global *rate.Limiter
	perIP  *ipRateLimiter
}

type ipRateLimiter struct {
	mu        sync.Mutex
	rate      rate.Limit
	burst     int
	ttl       time.Duration
	entries   map[string]*ipLimiterEntry
	lastSweep time.Time
}

type ipLimiterEntry struct {
	limiter *rate.Limiter
	last    time.Time
}

func newHandshakeLimiter(globalPPS, globalBurst int, ipPPS, ipBurst int, ttl time.Duration) *handshakeLimiter {
	var global *rate.Limiter
	if globalPPS > 0 && globalBurst > 0 {
		global = rate.NewLimiter(rate.Limit(globalPPS), globalBurst)
	}
	var perIP *ipRateLimiter
	if ipPPS > 0 && ipBurst > 0 {
		if ttl <= 0 {
			ttl = 1 * time.Minute
		}
		perIP = &ipRateLimiter{
			rate:    rate.Limit(ipPPS),
			burst:   ipBurst,
			ttl:     ttl,
			entries: make(map[string]*ipLimiterEntry),
		}
	}
	return &handshakeLimiter{global: global, perIP: perIP}
}

func (l *handshakeLimiter) Allow(ip string) bool {
	if l == nil {
		return true
	}
	if l.global != nil && !l.global.Allow() {
		return false
	}
	if l.perIP != nil && ip != "" {
		return l.perIP.Allow(ip)
	}
	return true
}

func (l *ipRateLimiter) Allow(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	if l.ttl > 0 && now.Sub(l.lastSweep) > l.ttl {
		l.sweepLocked(now)
		l.lastSweep = now
	}
	entry := l.entries[ip]
	if entry == nil {
		entry = &ipLimiterEntry{limiter: rate.NewLimiter(l.rate, l.burst)}
		l.entries[ip] = entry
	}
	entry.last = now
	return entry.limiter.Allow()
}

func (l *ipRateLimiter) sweepLocked(now time.Time) {
	for ip, entry := range l.entries {
		if now.Sub(entry.last) > l.ttl {
			delete(l.entries, ip)
		}
	}
}

func remoteIP(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return strings.TrimSpace(addr)
	}
	return host
}
