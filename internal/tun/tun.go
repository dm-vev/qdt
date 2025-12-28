package tun

import (
	"fmt"

	"github.com/songgao/water"
)

// Device wraps the TUN interface.
type Device struct {
	Interface *water.Interface
	Name      string
}

// Open creates a TUN interface with the given name (empty uses system default).
func Open(name string) (*Device, error) {
	cfg := water.Config{DeviceType: water.TUN}
	cfg.Name = name
	iface, err := water.New(cfg)
	if err != nil {
		return nil, fmt.Errorf("create TUN: %w", err)
	}
	return &Device{Interface: iface, Name: iface.Name()}, nil
}

// Read reads a packet from the TUN device.
func (d *Device) Read(buf []byte) (int, error) {
	return d.Interface.Read(buf)
}

// Write writes a packet to the TUN device.
func (d *Device) Write(buf []byte) (int, error) {
	return d.Interface.Write(buf)
}

// Close closes the TUN device.
func (d *Device) Close() error {
	return d.Interface.Close()
}
