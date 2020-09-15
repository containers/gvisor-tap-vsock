package types

import "net"

type Configuration struct {
	Debug       bool
	CaptureFile string

	MTU int

	Subnet            string
	GatewayIP         string
	GatewayMacAddress string

	DNSRecords map[string]net.IP
}
