//go:build windows

package netcfg

import (
	"fmt"
	"net"
	"os/exec"
	"strings"
)

func ConfigureInterface(cfg InterfaceConfig) error {
	ip, ipnet, err := net.ParseCIDR(cfg.Address)
	if err != nil {
		return fmt.Errorf("parse addr: %w", err)
	}
	mask := net.IP(ipnet.Mask).String()
	gateway := cfg.Gateway
	if gateway == "" {
		gateway = "none"
	}
	args := []string{"interface", "ip", "set", "address", fmt.Sprintf("name=%s", cfg.Name), "static", ip.String(), mask, gateway}
	if err := exec.Command("netsh", args...).Run(); err != nil {
		return fmt.Errorf("netsh set address: %w", err)
	}
	if cfg.MTU > 0 {
		mtuArgs := []string{"interface", "ipv4", "set", "subinterface", cfg.Name, fmt.Sprintf("mtu=%d", cfg.MTU), "store=persistent"}
		_ = exec.Command("netsh", mtuArgs...).Run()
	}
	return nil
}

func AddRoutes(ifName string, routes []Route) error {
	idx, err := interfaceIndex(ifName)
	if err != nil {
		return err
	}
	for _, r := range routes {
		ip, mask, err := parseCIDR(r.Dest)
		if err != nil {
			return err
		}
		gw := r.Gateway
		if gw == "" {
			gw = "0.0.0.0"
		}
		args := []string{"ADD", ip, "MASK", mask, gw, "IF", fmt.Sprintf("%d", idx)}
		_ = exec.Command("route", args...).Run()
	}
	return nil
}

func DeleteRoutes(ifName string, routes []Route) error {
	idx, err := interfaceIndex(ifName)
	if err != nil {
		return err
	}
	for _, r := range routes {
		ip, mask, err := parseCIDR(r.Dest)
		if err != nil {
			return err
		}
		args := []string{"DELETE", ip, "MASK", mask, "IF", fmt.Sprintf("%d", idx)}
		_ = exec.Command("route", args...).Run()
	}
	return nil
}

func SetDNS(ifName string, dns []string) error {
	if len(dns) == 0 {
		return nil
	}
	args := []string{"interface", "ip", "set", "dns", fmt.Sprintf("name=%s", ifName), "static", dns[0]}
	if err := exec.Command("netsh", args...).Run(); err != nil {
		return fmt.Errorf("netsh set dns: %w", err)
	}
	for i := 1; i < len(dns); i++ {
		addArgs := []string{"interface", "ip", "add", "dns", fmt.Sprintf("name=%s", ifName), dns[i], fmt.Sprintf("index=%d", i+1)}
		_ = exec.Command("netsh", addArgs...).Run()
	}
	return nil
}

func ResetDNS(ifName string) error {
	args := []string{"interface", "ip", "set", "dns", fmt.Sprintf("name=%s", ifName), "dhcp"}
	if err := exec.Command("netsh", args...).Run(); err != nil {
		return fmt.Errorf("netsh set dns dhcp: %w", err)
	}
	return nil
}

func EnableIPForwarding() error              { return nil }
func SetupNAT(cidr, outIface string) error   { return nil }
func CleanupNAT(cidr, outIface string) error { return nil }

func interfaceIndex(name string) (int, error) {
	name = strings.TrimSpace(name)
	ifaces, err := net.Interfaces()
	if err != nil {
		return 0, fmt.Errorf("interfaces: %w", err)
	}
	for _, iface := range ifaces {
		if iface.Name == name {
			return iface.Index, nil
		}
	}
	return 0, fmt.Errorf("interface not found: %s", name)
}

func parseCIDR(cidr string) (ip string, mask string, err error) {
	if cidr == "" {
		return "0.0.0.0", "0.0.0.0", nil
	}
	netIP, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return "", "", fmt.Errorf("parse cidr: %w", err)
	}
	return netIP.String(), net.IP(ipnet.Mask).String(), nil
}
