package qdt

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
)

const (
	ProtocolVersion uint8 = 1
	Magic                 = "QDT"

	ConnectPath = "/connect"
	TokenHeader = "X-QDT-Token"

	DefaultMTU   = 1350
	MaxBodyBytes = 4096

	HeaderLen = 3 + 1 + 1 + 1 + 8 + 8
)

var (
	ErrInvalidDatagram = errors.New("invalid datagram")
	ErrBadMagic        = errors.New("invalid datagram magic")
	ErrBadVersion      = errors.New("unsupported datagram version")
)

type MessageType uint8

const (
	MsgData MessageType = iota
	MsgFragment
	MsgPing
	MsgPong
	MsgClose
)

type ConnectRequest struct {
	Version     uint8    `json:"version"`
	ClientNonce string   `json:"client_nonce"`
	MTU         int      `json:"mtu"`
	Caps        []string `json:"caps,omitempty"`
	ClientID    string   `json:"client_id,omitempty"`
	Platform    string   `json:"platform,omitempty"`
}

type ConnectResponse struct {
	Version     uint8    `json:"version"`
	SessionID   uint64   `json:"session_id"`
	ServerNonce string   `json:"server_nonce"`
	MTU         int      `json:"mtu"`
	ClientIP    string   `json:"client_ip"`
	GatewayIP   string   `json:"gateway_ip"`
	CIDR        string   `json:"cidr"`
	DNS         []string `json:"dns,omitempty"`
	Caps        []string `json:"caps,omitempty"`
}

func NewConnectRequest(clientNonce []byte, mtu int, caps []string, clientID, platform string) ConnectRequest {
	if mtu <= 0 {
		mtu = DefaultMTU
	}
	return ConnectRequest{
		Version:     ProtocolVersion,
		ClientNonce: EncodeNonce(clientNonce),
		MTU:         mtu,
		Caps:        caps,
		ClientID:    clientID,
		Platform:    platform,
	}
}

func DecodeConnectRequest(r io.Reader) (ConnectRequest, error) {
	var req ConnectRequest
	limited := io.LimitReader(r, MaxBodyBytes)
	dec := json.NewDecoder(limited)
	if err := dec.Decode(&req); err != nil {
		return ConnectRequest{}, fmt.Errorf("decode connect request: %w", err)
	}
	if req.Version != ProtocolVersion {
		return ConnectRequest{}, fmt.Errorf("unsupported protocol version: %d", req.Version)
	}
	if req.MTU <= 0 {
		req.MTU = DefaultMTU
	}
	return req, nil
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

func EncodeNonce(b []byte) string {
	return base64.RawStdEncoding.EncodeToString(b)
}

func DecodeNonce(s string) ([]byte, error) {
	return base64.RawStdEncoding.DecodeString(s)
}
