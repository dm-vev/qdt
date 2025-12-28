package qdt

import (
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync/atomic"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

const (
	HandshakeNonceSize = 16
	NoncePrefixSize    = 4
)

var (
	ErrReplay = errors.New("replay detected")
)

type KeyMaterial struct {
	ClientKey         [chacha20poly1305.KeySize]byte
	ServerKey         [chacha20poly1305.KeySize]byte
	ClientNoncePrefix [NoncePrefixSize]byte
	ServerNoncePrefix [NoncePrefixSize]byte
}

func NewHandshakeNonce() ([]byte, error) {
	b := make([]byte, HandshakeNonceSize)
	if _, err := rand.Read(b); err != nil {
		return nil, fmt.Errorf("handshake nonce: %w", err)
	}
	return b, nil
}

func DeriveKeyMaterial(token string, clientNonce, serverNonce []byte) (KeyMaterial, error) {
	if token == "" {
		return KeyMaterial{}, errors.New("token is empty")
	}
	if len(clientNonce) != HandshakeNonceSize || len(serverNonce) != HandshakeNonceSize {
		return KeyMaterial{}, fmt.Errorf("nonce must be %d bytes", HandshakeNonceSize)
	}
	salt := append(append([]byte{}, clientNonce...), serverNonce...)
	r := hkdf.New(sha256.New, []byte(token), salt, []byte("qdt-aead-v1"))
	var out [chacha20poly1305.KeySize*2 + NoncePrefixSize*2]byte
	if _, err := io.ReadFull(r, out[:]); err != nil {
		return KeyMaterial{}, fmt.Errorf("hkdf: %w", err)
	}
	var km KeyMaterial
	off := 0
	copy(km.ClientKey[:], out[off:off+chacha20poly1305.KeySize])
	off += chacha20poly1305.KeySize
	copy(km.ServerKey[:], out[off:off+chacha20poly1305.KeySize])
	off += chacha20poly1305.KeySize
	copy(km.ClientNoncePrefix[:], out[off:off+NoncePrefixSize])
	off += NoncePrefixSize
	copy(km.ServerNoncePrefix[:], out[off:off+NoncePrefixSize])
	return km, nil
}

type CipherState struct {
	aead        cipher.AEAD
	noncePrefix [NoncePrefixSize]byte
	sendCounter uint64
	replay      *ReplayWindow
}

func NewCipherState(key [chacha20poly1305.KeySize]byte, noncePrefix [NoncePrefixSize]byte, replay *ReplayWindow) (*CipherState, error) {
	aead, err := chacha20poly1305.New(key[:])
	if err != nil {
		return nil, fmt.Errorf("aead: %w", err)
	}
	return &CipherState{aead: aead, noncePrefix: noncePrefix, replay: replay}, nil
}

func NewClientCipherStates(km KeyMaterial, replay *ReplayWindow) (send *CipherState, recv *CipherState, err error) {
	send, err = NewCipherState(km.ClientKey, km.ClientNoncePrefix, nil)
	if err != nil {
		return nil, nil, err
	}
	recv, err = NewCipherState(km.ServerKey, km.ServerNoncePrefix, replay)
	if err != nil {
		return nil, nil, err
	}
	return send, recv, nil
}

func NewServerCipherStates(km KeyMaterial, replay *ReplayWindow) (send *CipherState, recv *CipherState, err error) {
	send, err = NewCipherState(km.ServerKey, km.ServerNoncePrefix, nil)
	if err != nil {
		return nil, nil, err
	}
	recv, err = NewCipherState(km.ClientKey, km.ClientNoncePrefix, replay)
	if err != nil {
		return nil, nil, err
	}
	return send, recv, nil
}

func (c *CipherState) NextCounter() uint64 {
	return atomic.AddUint64(&c.sendCounter, 1) - 1
}

func (c *CipherState) nonce(counter uint64) [chacha20poly1305.NonceSize]byte {
	var nonce [chacha20poly1305.NonceSize]byte
	copy(nonce[:NoncePrefixSize], c.noncePrefix[:])
	binary.BigEndian.PutUint64(nonce[NoncePrefixSize:], counter)
	return nonce
}

func (c *CipherState) Seal(dst []byte, counter uint64, aad, plaintext []byte) []byte {
	nonce := c.nonce(counter)
	return c.aead.Seal(dst, nonce[:], plaintext, aad)
}

func (c *CipherState) Open(dst []byte, counter uint64, aad, ciphertext []byte) ([]byte, error) {
	if c.replay != nil {
		ok := c.replay.Check(counter)
		if !ok {
			return nil, ErrReplay
		}
	}
	nonce := c.nonce(counter)
	pt, err := c.aead.Open(dst, nonce[:], ciphertext, aad)
	if err != nil {
		return nil, err
	}
	if c.replay != nil {
		c.replay.Mark(counter)
	}
	return pt, nil
}

func (c *CipherState) Overhead() int {
	return c.aead.Overhead()
}
