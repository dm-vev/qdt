package qdt

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
)

const (
	ProtocolVersion = 1
	Magic           = "QDT"

	ConnectPath  = "/connect"
	TokenHeader  = "X-QDT-Token"
	DefaultMTU   = 1350
	HeaderLen    = 18
	MaxBodyBytes = 4096
)

var (
	ErrInvalidDatagram = errors.New("invalid datagram")
	ErrBadMagic        = errors.New("invalid datagram magic")
	ErrBadVersion      = errors.New("unsupported datagram version")
)

type MessageType uint8

const (
	MsgData MessageType = iota
	MsgPing
	MsgPong
	MsgClose
)

type Datagram struct {
	Version   uint8
	Type      MessageType
	Flags     uint8
	SessionID uint64
	Counter   uint32
	Payload   []byte
}

func NewSessionID() (uint64, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0, fmt.Errorf("session id: %w", err)
	}
	return binary.BigEndian.Uint64(b[:]), nil
}

func NewDataDatagram(sessionID uint64, counter uint32, payload []byte) Datagram {
	return Datagram{
		Version:   ProtocolVersion,
		Type:      MsgData,
		SessionID: sessionID,
		Counter:   counter,
		Payload:   payload,
	}
}

func AppendDatagram(dst []byte, d Datagram) ([]byte, error) {
	if len(Magic) != 3 {
		return nil, fmt.Errorf("magic length must be 3")
	}
	start := len(dst)
	dst = append(dst, make([]byte, HeaderLen)...)
	copy(dst[start:start+3], Magic)
	dst[start+3] = d.Version
	dst[start+4] = byte(d.Type)
	dst[start+5] = d.Flags
	binary.BigEndian.PutUint64(dst[start+6:start+14], d.SessionID)
	binary.BigEndian.PutUint32(dst[start+14:start+18], d.Counter)
	dst = append(dst, d.Payload...)
	return dst, nil
}

func ParseDatagram(b []byte) (Datagram, error) {
	if len(b) < HeaderLen {
		return Datagram{}, ErrInvalidDatagram
	}
	if string(b[:3]) != Magic {
		return Datagram{}, ErrBadMagic
	}
	if b[3] != ProtocolVersion {
		return Datagram{}, ErrBadVersion
	}
	d := Datagram{
		Version:   b[3],
		Type:      MessageType(b[4]),
		Flags:     b[5],
		SessionID: binary.BigEndian.Uint64(b[6:14]),
		Counter:   binary.BigEndian.Uint32(b[14:18]),
		Payload:   b[HeaderLen:],
	}
	return d, nil
}

type ConnectResponse struct {
	Version   uint8  `json:"version"`
	SessionID uint64 `json:"session_id"`
	MTU       int    `json:"mtu"`
}

func WriteConnectResponse(w http.ResponseWriter, resp ConnectResponse) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	enc := json.NewEncoder(w)
	return enc.Encode(resp)
}

func ReadConnectResponse(r io.Reader) (ConnectResponse, error) {
	var resp ConnectResponse
	limited := io.LimitReader(r, MaxBodyBytes)
	dec := json.NewDecoder(limited)
	if err := dec.Decode(&resp); err != nil {
		return ConnectResponse{}, fmt.Errorf("decode connect response: %w", err)
	}
	if resp.Version != ProtocolVersion {
		return ConnectResponse{}, fmt.Errorf("unsupported protocol version: %d", resp.Version)
	}
	if resp.MTU <= 0 {
		resp.MTU = DefaultMTU
	}
	return resp, nil
}
