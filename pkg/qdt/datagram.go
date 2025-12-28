package qdt

import "encoding/binary"

type Header struct {
	Version   uint8
	Type      MessageType
	Flags     uint8
	SessionID uint64
	Counter   uint64
}

func WriteHeader(b []byte, h Header) {
	if len(b) < HeaderLen {
		return
	}
	copy(b[0:3], Magic)
	b[3] = h.Version
	b[4] = byte(h.Type)
	b[5] = h.Flags
	binary.BigEndian.PutUint64(b[6:14], h.SessionID)
	binary.BigEndian.PutUint64(b[14:22], h.Counter)
}

func AppendHeader(dst []byte, h Header) []byte {
	start := len(dst)
	dst = append(dst, make([]byte, HeaderLen)...)
	WriteHeader(dst[start:start+HeaderLen], h)
	return dst
}

func ParseHeader(b []byte) (Header, []byte, error) {
	if len(b) < HeaderLen {
		return Header{}, nil, ErrInvalidDatagram
	}
	if string(b[:3]) != Magic {
		return Header{}, nil, ErrBadMagic
	}
	version := b[3]
	if version != ProtocolVersion {
		return Header{}, nil, ErrBadVersion
	}
	h := Header{
		Version:   version,
		Type:      MessageType(b[4]),
		Flags:     b[5],
		SessionID: binary.BigEndian.Uint64(b[6:14]),
		Counter:   binary.BigEndian.Uint64(b[14:22]),
	}
	return h, b[HeaderLen:], nil
}
