package types

type TransportProtocol string

const (
	UDP   TransportProtocol = "udp"
	TCP   TransportProtocol = "tcp"
	UNIX  TransportProtocol = "unix"
	NPIPE TransportProtocol = "npipe"
)

type ExposeRequest struct {
	Local    string            `json:"local"`
	Remote   string            `json:"remote"`
	Protocol TransportProtocol `json:"protocol"`
}

type UnexposeRequest struct {
	Local    string            `json:"local"`
	Protocol TransportProtocol `json:"protocol"`
}

type NotificationMessage struct {
	NotificationType NotificationType `json:"notification_type"`
}

type NotificationType string

const (
	Ready                 NotificationType = "ready"
	ConnectionEstablished NotificationType = "connection_established"
	HypervisorWarning     NotificationType = "hypervisor_warning"
	HypervisorError       NotificationType = "hypervisor_error"
)
