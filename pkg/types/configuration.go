package types

type Configuration struct {
	Debug       bool
	CaptureFile string

	Endpoint string
	MTU      int

	Subnet     string
	SubnetMask string

	GatewayIP         string
	GatewayMacAddress string

	VMIP string
}
