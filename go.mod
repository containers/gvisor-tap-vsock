module github.com/containers/gvisor-tap-vsock

go 1.16

require (
	github.com/Microsoft/go-winio v0.5.2
	github.com/apparentlymart/go-cidr v1.1.0
	github.com/coreos/stream-metadata-go v0.4.0
	github.com/dustin/go-humanize v1.0.0
	github.com/google/gopacket v1.1.19
	github.com/insomniacslk/dhcp v0.0.0-20220504074936-1ca156eafb9f
	github.com/linuxkit/virtsock v0.0.0-20220523201153-1a23e78aa7a2
	github.com/mdlayher/vsock v1.1.1
	github.com/miekg/dns v1.1.50
	github.com/onsi/ginkgo v1.16.5
	github.com/onsi/gomega v1.22.1
	github.com/opencontainers/go-digest v1.0.0
	github.com/pkg/errors v0.9.1
	github.com/sirupsen/logrus v1.9.0
	github.com/songgao/packets v0.0.0-20160404182456-549a10cd4091
	github.com/songgao/water v0.0.0-20200317203138-2b4b6d7c09d8
	github.com/stretchr/testify v1.8.0
	github.com/vishvananda/netlink v1.1.1-0.20201029203352-d40f9887b852
	golang.org/x/crypto v0.0.0-20220722155217-630584e8d5aa
	golang.org/x/sync v0.0.0-20220722155255-886fb9371eb4
	golang.org/x/sys v0.0.0-20220722155257-8c9f86f7a55f
	gvisor.dev/gvisor v0.0.0-20220908032458-edc830a43ba6
	inet.af/tcpproxy v0.0.0-20220326234310-be3ee21c9fa0
)
