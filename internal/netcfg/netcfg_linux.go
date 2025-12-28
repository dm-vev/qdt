//go:build linux

package netcfg

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"

	"github.com/vishvananda/netlink"
)

func ConfigureInterface(cfg InterfaceConfig) error {
	link, err := netlink.LinkByName(cfg.Name)
	if err != nil {
		return fmt.Errorf("link %s: %w", cfg.Name, err)
	}
	if cfg.MTU > 0 {
		if err := netlink.LinkSetMTU(link, cfg.MTU); err != nil {
			return fmt.Errorf("set mtu: %w", err)
		}
	}
	if cfg.Address != "" {
		addr, err := netlink.ParseAddr(cfg.Address)
		if err != nil {
			return fmt.Errorf("parse addr: %w", err)
		}
		_ = netlink.AddrDel(link, addr)
		if err := netlink.AddrAdd(link, addr); err != nil {
			return fmt.Errorf("addr add: %w", err)
		}
	}
	if err := netlink.LinkSetUp(link); err != nil {
		return fmt.Errorf("link up: %w", err)
	}
	return nil
}

func AddRoutes(ifName string, routes []Route) error {
	link, err := netlink.LinkByName(ifName)
	if err != nil {
		return fmt.Errorf("link %s: %w", ifName, err)
	}
	for _, r := range routes {
		route, err := buildRoute(link, r)
		if err != nil {
			return err
		}
		_ = netlink.RouteDel(route)
		if err := netlink.RouteAdd(route); err != nil {
			return fmt.Errorf("route add: %w", err)
		}
	}
	return nil
}

func DeleteRoutes(ifName string, routes []Route) error {
	link, err := netlink.LinkByName(ifName)
	if err != nil {
		return fmt.Errorf("link %s: %w", ifName, err)
	}
	for _, r := range routes {
		route, err := buildRoute(link, r)
		if err != nil {
			return err
		}
		_ = netlink.RouteDel(route)
	}
	return nil
}

func SetDNS(ifName string, dns []string) error {
	if len(dns) == 0 {
		return nil
	}
	path, err := exec.LookPath("resolvectl")
	if err != nil {
		return nil
	}
	args := append([]string{"dns", ifName}, dns...)
	cmd := exec.Command(path, args...)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("resolvectl dns: %w", err)
	}
	cmd = exec.Command(path, "domain", ifName, "~.")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("resolvectl domain: %w", err)
	}
	return nil
}

func EnableIPForwarding() error {
	return os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1"), 0644)
}

func SetupNAT(cidr, outIface string) error {
	if cidr == "" || outIface == "" {
		return nil
	}
	args := []string{"-t", "nat", "-A", "POSTROUTING", "-s", cidr, "-o", outIface, "-j", "MASQUERADE"}
	if err := exec.Command("iptables", args...).Run(); err != nil {
		return fmt.Errorf("iptables nat: %w", err)
	}
	forwardArgs := []string{"-A", "FORWARD", "-s", cidr, "-o", outIface, "-j", "ACCEPT"}
	_ = exec.Command("iptables", forwardArgs...).Run()
	return nil
}

func CleanupNAT(cidr, outIface string) error {
	if cidr == "" || outIface == "" {
		return nil
	}
	args := []string{"-t", "nat", "-D", "POSTROUTING", "-s", cidr, "-o", outIface, "-j", "MASQUERADE"}
	_ = exec.Command("iptables", args...).Run()
	forwardArgs := []string{"-D", "FORWARD", "-s", cidr, "-o", outIface, "-j", "ACCEPT"}
	_ = exec.Command("iptables", forwardArgs...).Run()
	return nil
}

func buildRoute(link netlink.Link, r Route) (*netlink.Route, error) {
	var dst *net.IPNet
	if r.Dest != "" {
		_, ipnet, err := net.ParseCIDR(r.Dest)
		if err != nil {
			return nil, fmt.Errorf("parse route dst: %w", err)
		}
		dst = ipnet
	}
	var gw net.IP
	if r.Gateway != "" {
		gw = net.ParseIP(r.Gateway)
		if gw == nil {
			return nil, fmt.Errorf("parse route gw")
		}
	}
	if dst == nil {
		_, ipnet, _ := net.ParseCIDR("0.0.0.0/0")
		dst = ipnet
	}
	return &netlink.Route{
		LinkIndex: link.Attrs().Index,
		Dst:       dst,
		Gw:        gw,
	}, nil
}

func InterfaceIndexByName(name string) (int, error) {
	link, err := netlink.LinkByName(name)
	if err != nil {
		return 0, err
	}
	return link.Attrs().Index, nil
}

func NormalizeInterfaceName(name string) string {
	return strings.TrimSpace(name)
}
