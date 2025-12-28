//go:build linux

package tun

import (
	"fmt"

	"github.com/songgao/water"
)

// Device wraps a TUN interface.
type Device struct {
	Interface *water.Interface
	Name      string
}

func Open(name string) (*Device, error) {
	cfg := water.Config{DeviceType: water.TUN}
	cfg.Name = name
	iface, err := water.New(cfg)
	if err != nil {
		return nil, fmt.Errorf("create tun: %w", err)
	}
	return &Device{Interface: iface, Name: iface.Name()}, nil
}

func (d *Device) Read(buf []byte) (int, error) {
	return d.Interface.Read(buf)
}

func (d *Device) Write(buf []byte) (int, error) {
	return d.Interface.Write(buf)
}

func (d *Device) Close() error {
	return d.Interface.Close()
}
