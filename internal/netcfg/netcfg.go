package netcfg

type InterfaceConfig struct {
	Name    string
	Address string
	Gateway string
	MTU     int
}

type Route struct {
	Dest    string
	Gateway string
}
