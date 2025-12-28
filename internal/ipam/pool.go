package ipam

import (
	"encoding/binary"
	"fmt"
	"net"
	"sync"
)

type Pool struct {
	mu       sync.Mutex
	base     uint32
	max      uint32
	next     uint32
	used     map[uint32]bool
	reserved map[uint32]bool
	cidr     string
}

func New(cidr string, reserve []net.IP) (*Pool, error) {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("parse cidr: %w", err)
	}
	ipv4 := ip.To4()
	if ipv4 == nil {
		return nil, fmt.Errorf("only ipv4 supported for pool")
	}
	netIP := ipnet.IP.To4()
	mask := binary.BigEndian.Uint32(ipnet.Mask)
	netUint := binary.BigEndian.Uint32(netIP)
	broadcast := netUint | ^mask
	if broadcast-netUint < 3 {
		return nil, fmt.Errorf("cidr too small")
	}
	base := netUint + 1
	max := broadcast - 1

	res := make(map[uint32]bool)
	for _, ip := range reserve {
		v4 := ip.To4()
		if v4 == nil {
			continue
		}
		res[binary.BigEndian.Uint32(v4)] = true
	}
	res[netUint] = true
	res[broadcast] = true

	return &Pool{
		base:     base,
		max:      max,
		next:     base,
		used:     make(map[uint32]bool),
		reserved: res,
		cidr:     cidr,
	}, nil
}

func (p *Pool) CIDR() string {
	return p.cidr
}

func (p *Pool) Acquire() (net.IP, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	span := p.max - p.base + 1
	for i := uint32(0); i < span; i++ {
		candidate := p.base + ((p.next - p.base + i) % span)
		if p.used[candidate] || p.reserved[candidate] {
			continue
		}
		p.used[candidate] = true
		p.next = candidate + 1
		return uint32ToIP(candidate), nil
	}
	return nil, fmt.Errorf("address pool exhausted")
}

func (p *Pool) Release(ip net.IP) {
	p.mu.Lock()
	defer p.mu.Unlock()
	v4 := ip.To4()
	if v4 == nil {
		return
	}
	delete(p.used, binary.BigEndian.Uint32(v4))
}

func uint32ToIP(v uint32) net.IP {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], v)
	return net.IPv4(b[0], b[1], b[2], b[3])
}
