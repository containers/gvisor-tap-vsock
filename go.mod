module github.com/containers/gvisor-tap-vsock

go 1.16

require (
	github.com/Microsoft/go-winio v0.5.2
	github.com/apparentlymart/go-cidr v1.1.0
	github.com/coreos/stream-metadata-go v0.3.0
	github.com/dustin/go-humanize v1.0.0
	github.com/google/gopacket v1.1.19
	github.com/google/tcpproxy v0.0.0-20200125044825-b6bb9b5b8252
	github.com/insomniacslk/dhcp v0.0.0-20210812084645-decc701b3665
	github.com/linuxkit/virtsock v0.0.0-20201010232012-f8cee7dfc7a3
	github.com/mdlayher/vsock v1.1.1
	github.com/miekg/dns v1.1.49
	github.com/onsi/ginkgo v1.16.5
	github.com/onsi/gomega v1.18.1
	github.com/opencontainers/go-digest v1.0.0
	github.com/pkg/errors v0.9.1
	github.com/sirupsen/logrus v1.8.1
	github.com/songgao/packets v0.0.0-20160404182456-549a10cd4091
	github.com/songgao/water v0.0.0-20200317203138-2b4b6d7c09d8
	github.com/stretchr/testify v1.7.0
	github.com/vishvananda/netlink v1.1.1-0.20201029203352-d40f9887b852
	golang.org/x/crypto v0.0.0-20210711020723-a769d52b0f97
	golang.org/x/net v0.0.0-20220127200216-cd36cc0744dd // indirect
	golang.org/x/sync v0.0.0-20210220032951-036812b2e83c
	golang.org/x/sys v0.0.0-20220204135822-1c1b9b1eba6a
	golang.org/x/time v0.0.0-20200630173020-3af7569d3a1e // indirect
	gopkg.in/check.v1 v1.0.0-20190902080502-41f04d3bba15 // indirect
	gopkg.in/yaml.v3 v3.0.0-20210107192922-496545a6307b // indirect
	gvisor.dev/gvisor v0.0.0-20220121190119-4f2d380c8b55
)
