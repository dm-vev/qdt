//go:build !linux && !windows

package netcfg

import "errors"

var errNotSupported = errors.New("not supported")

func ConfigureInterface(cfg InterfaceConfig) error     { return errNotSupported }
func AddRoutes(ifName string, routes []Route) error    { return errNotSupported }
func DeleteRoutes(ifName string, routes []Route) error { return errNotSupported }
func SetDNS(ifName string, dns []string) error         { return errNotSupported }
func ResetDNS(ifName string) error                     { return errNotSupported }
func EnableIPForwarding() error                        { return errNotSupported }
func SetupNAT(cidr, outIface string) error             { return errNotSupported }
func CleanupNAT(cidr, outIface string) error           { return errNotSupported }
