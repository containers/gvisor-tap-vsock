package types

type Configuration struct {
	Debug       bool
	CaptureFile string

	MTU int

	Subnet            string
	GatewayIP         string
	GatewayMacAddress string
}
