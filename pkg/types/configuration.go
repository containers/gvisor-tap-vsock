package types

type Configuration struct {
	Debug       bool
	CaptureFile string

	Endpoints []string
	MTU       int

	Subnet            string
	GatewayIP         string
	GatewayMacAddress string
}
