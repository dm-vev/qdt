package iputil

import (
	"encoding/binary"
	"errors"
	"net"
)

var (
	ErrPacketTooShort = errors.New("packet too short")
	ErrUnknownIP      = errors.New("unknown ip version")
)

func PacketSource(pkt []byte) (net.IP, error) {
	ver, err := ipVersion(pkt)
	if err != nil {
		return nil, err
	}
	switch ver {
	case 4:
		if len(pkt) < 20 {
			return nil, ErrPacketTooShort
		}
		ihl := int(pkt[0]&0x0F) * 4
		if len(pkt) < ihl {
			return nil, ErrPacketTooShort
		}
		return net.IPv4(pkt[12], pkt[13], pkt[14], pkt[15]), nil
	case 6:
		if len(pkt) < 40 {
			return nil, ErrPacketTooShort
		}
		ip := make(net.IP, net.IPv6len)
		copy(ip, pkt[8:24])
		return ip, nil
	default:
		return nil, ErrUnknownIP
	}
}

func PacketDest(pkt []byte) (net.IP, error) {
	ver, err := ipVersion(pkt)
	if err != nil {
		return nil, err
	}
	switch ver {
	case 4:
		if len(pkt) < 20 {
			return nil, ErrPacketTooShort
		}
		ihl := int(pkt[0]&0x0F) * 4
		if len(pkt) < ihl {
			return nil, ErrPacketTooShort
		}
		return net.IPv4(pkt[16], pkt[17], pkt[18], pkt[19]), nil
	case 6:
		if len(pkt) < 40 {
			return nil, ErrPacketTooShort
		}
		ip := make(net.IP, net.IPv6len)
		copy(ip, pkt[24:40])
		return ip, nil
	default:
		return nil, ErrUnknownIP
	}
}

func ipVersion(pkt []byte) (int, error) {
	if len(pkt) == 0 {
		return 0, ErrPacketTooShort
	}
	return int(pkt[0] >> 4), nil
}

// PacketSourceV4 returns the IPv4 source address as uint32.
func PacketSourceV4(pkt []byte) (uint32, bool) {
	if len(pkt) < 20 {
		return 0, false
	}
	if pkt[0]>>4 != 4 {
		return 0, false
	}
	ihl := int(pkt[0]&0x0F) * 4
	if len(pkt) < ihl || ihl < 20 {
		return 0, false
	}
	return binary.BigEndian.Uint32(pkt[12:16]), true
}

// PacketDestV4 returns the IPv4 destination address as uint32.
func PacketDestV4(pkt []byte) (uint32, bool) {
	if len(pkt) < 20 {
		return 0, false
	}
	if pkt[0]>>4 != 4 {
		return 0, false
	}
	ihl := int(pkt[0]&0x0F) * 4
	if len(pkt) < ihl || ihl < 20 {
		return 0, false
	}
	return binary.BigEndian.Uint32(pkt[16:20]), true
}
