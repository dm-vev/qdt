//go:build windows

package tun

import (
	"fmt"

	"golang.zx2c4.com/wintun"
)

// Device wraps a Wintun session.
type Device struct {
	adapter *wintun.Adapter
	session *wintun.Session
	Name    string
}

func Open(name string) (*Device, error) {
	adapter, err := wintun.CreateAdapter(name, "QDT", nil)
	if err != nil {
		adapter, err = wintun.OpenAdapter(name)
		if err != nil {
			return nil, fmt.Errorf("open adapter: %w", err)
		}
	}
	session, err := adapter.StartSession(0x800000)
	if err != nil {
		adapter.Close()
		return nil, fmt.Errorf("start session: %w", err)
	}
	return &Device{adapter: adapter, session: session, Name: adapter.Name()}, nil
}

func (d *Device) Read(buf []byte) (int, error) {
	packet, err := d.session.ReceivePacket()
	if err != nil {
		return 0, err
	}
	n := copy(buf, packet)
	d.session.ReleaseReceivePacket(packet)
	return n, nil
}

func (d *Device) Write(buf []byte) (int, error) {
	packet, err := d.session.AllocateSendPacket(len(buf))
	if err != nil {
		return 0, err
	}
	copy(packet, buf)
	d.session.SendPacket(packet)
	return len(buf), nil
}

func (d *Device) Close() error {
	if d.session != nil {
		d.session.End()
	}
	if d.adapter != nil {
		d.adapter.Close()
	}
	return nil
}
