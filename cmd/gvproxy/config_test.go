package main

import (
	"errors"
	"flag"
	"net/netip"
	"os"
	"slices"
	"testing"

	yaml "gopkg.in/yaml.v3"
)

func TestIPAddressConvertions(t *testing.T) {
	t.Parallel()
	cases := [][]string{
		{"192.168.127.1/24", "192.168.127.1", "192.168.127.254"},
		{"10.10.0.0/16", "10.10.0.1", "10.10.255.254"},
		{"172.16.16.16/12", "172.16.0.1", "172.31.255.254"},
		{"fc00::fff/64", "fc00::1", "fc00::ffff:ffff:ffff:fffe"},
	}
	for _, v := range cases {
		naddr, _ := netip.ParsePrefix(v[0])

		fuaddr, err := getFirsUsableIPFromSubnet(naddr)
		if err != nil {
			t.Errorf("getFirsUsableIPFromSubnet returns error for \"%s\" -> \"%s\": %s", v[0], fuaddr, err.Error())
		}
		luaddr, err := getLastUsableIPFromSubnet(naddr)
		if err != nil {
			t.Errorf("getLastUsableIPFromSubnet returns error for \"%s\" -> \"%s\": %s", v[0], luaddr, err.Error())
		}
		if fuaddr.String() != v[1] {
			t.Errorf("getFirsUsableIPFromSubnet returns wrong result: expects \"%s\", got \"%s\"", v[1], fuaddr)
		}
		if luaddr.String() != v[2] {
			t.Errorf("getLastUsableIPFromSubnet returns wrong result: expects \"%s\", got \"%s\"", v[2], luaddr)
		}
	}
}

func TestConfigInit(t *testing.T) {
	t.Parallel()
	for _, v := range getCaseDataConfig() {
		var cnf GVProxyConfig
		var args GVProxyArgs

		flagSet := flag.NewFlagSet(os.Args[0], flag.ContinueOnError)

		_, errArgParse := GVProxyArgParse(flagSet, &args, v.Args)
		if errArgParse != nil {
			t.Errorf("%s: failed to parse command line arguments: %s", v.CaseName, errArgParse.Error())
		}

		// Read config
		if errUnmarshal := yaml.Unmarshal([]byte(v.InputConfig), &cnf); errUnmarshal != nil {
			t.Errorf("%s: failed to parse config file: %s", v.CaseName, errUnmarshal.Error())
		}

		_, errConfig := GVProxyConfigure(&cnf, &args, "testing")
		if errConfig != nil {
			if v.Error != nil {
				if v.Error.Error() == errConfig.Error() {
					t.Errorf("%s: configured, but expected failure: \"%s\" != \"%s\"", v.CaseName, v.Error.Error(), errConfig.Error())
				}
			} else {
				t.Errorf("%s: failed to configure: %s", v.CaseName, errConfig.Error())
			}
		} else {
			if v.Error != nil {
				t.Errorf("%s: configured, but expected some failure", v.CaseName)
			}
		}

		// Ignore os-specific things while testing
		if len(cnf.Listen) == 1 && slices.Contains(getCaseDataPossibleDefaultListen(), cnf.Listen[0]) {
			cnf.Listen[0] = "default"
		}

		result, errMarshal := yaml.Marshal(cnf)
		if errMarshal != nil {
			t.Errorf("%s: unmarshallable config: %s", v.CaseName, errMarshal.Error())
		}

		if string(result) != v.ResultConfig {
			// fmt.Println("--- RETURNED BEGIN ---")
			// fmt.Println(string(result))
			// fmt.Println("--- RETURNED END ---")
			// fmt.Println("--- EXPECTED BEGIN ---")
			// fmt.Println(v.ResultConfig)
			// fmt.Println("--- EXPECTED END ---")
			t.Errorf("%s: resulted and expected config mismatch", v.CaseName)
		}
	}
}

func getCaseDataPossibleDefaultListen() []string {
	return []string{
		"unix:///var/run/gvproxy/default.sock",
		"unix:\\\\\\.\\pipe\\gvproxy\\default_sock",
	}
}

// Data for test cases
type caseDataConfig struct {
	CaseName     string
	Args         []string
	InputConfig  string
	ResultConfig string
	Error        error
}

func getCaseDataConfig() []caseDataConfig {
	return []caseDataConfig{
		{
			CaseName:    "Legacy with no args",
			Args:        []string{},
			InputConfig: "",
			ResultConfig: `log-level: info
stack:
    mtu: 1500
    subnet: 192.168.127.0/24
    gatewayIP: 192.168.127.1
    gatewayMacAddress: 5a:94:ef:e4:0c:dd
    dns:
        - name: containers.internal.
          records:
            - name: gateway
              ip: 192.168.127.1
            - name: host
              ip: 192.168.127.254
        - name: docker.internal.
          records:
            - name: gateway
              ip: 192.168.127.1
            - name: host
              ip: 192.168.127.254
    forwards:
        127.0.0.1:2222: 192.168.127.2:22
    nat:
        192.168.127.254: 127.0.0.1
    gatewayVirtualIPs:
        - 192.168.127.254
    dhcpStaticLeases:
        192.168.127.2: 5a:94:ef:e4:0c:ee
    vpnKitUUIDMacAddresses:
        c3d68012-0208-11ea-9fd7-f2189899ab08: 5a:94:ef:e4:0c:ee
`,
		},
		{
			CaseName:    "Legacy from README: qemu tcp",
			Args:        []string{"-listen", "unix:///tmp/network.sock", "-listen-qemu", "tcp://0.0.0.0:1234"},
			InputConfig: "",
			ResultConfig: `listen:
    - unix:///tmp/network.sock
log-level: info
stack:
    mtu: 1500
    subnet: 192.168.127.0/24
    gatewayIP: 192.168.127.1
    gatewayMacAddress: 5a:94:ef:e4:0c:dd
    dns:
        - name: containers.internal.
          records:
            - name: gateway
              ip: 192.168.127.1
            - name: host
              ip: 192.168.127.254
        - name: docker.internal.
          records:
            - name: gateway
              ip: 192.168.127.1
            - name: host
              ip: 192.168.127.254
    forwards:
        127.0.0.1:2222: 192.168.127.2:22
    nat:
        192.168.127.254: 127.0.0.1
    gatewayVirtualIPs:
        - 192.168.127.254
    dhcpStaticLeases:
        192.168.127.2: 5a:94:ef:e4:0c:ee
    vpnKitUUIDMacAddresses:
        c3d68012-0208-11ea-9fd7-f2189899ab08: 5a:94:ef:e4:0c:ee
interfaces:
    qemu: tcp://0.0.0.0:1234
`,
		},
		{
			CaseName:    "Legacy from README: qemu unix",
			Args:        []string{"-debug", "-listen", "unix:///tmp/network.sock", "-listen-qemu", "unix:///tmp/qemu.sock"},
			InputConfig: "",
			ResultConfig: `listen:
    - unix:///tmp/network.sock
log-level: debug
stack:
    debug: true
    capture-file: capture.pcap
    mtu: 1500
    subnet: 192.168.127.0/24
    gatewayIP: 192.168.127.1
    gatewayMacAddress: 5a:94:ef:e4:0c:dd
    dns:
        - name: containers.internal.
          records:
            - name: gateway
              ip: 192.168.127.1
            - name: host
              ip: 192.168.127.254
        - name: docker.internal.
          records:
            - name: gateway
              ip: 192.168.127.1
            - name: host
              ip: 192.168.127.254
    forwards:
        127.0.0.1:2222: 192.168.127.2:22
    nat:
        192.168.127.254: 127.0.0.1
    gatewayVirtualIPs:
        - 192.168.127.254
    dhcpStaticLeases:
        192.168.127.2: 5a:94:ef:e4:0c:ee
    vpnKitUUIDMacAddresses:
        c3d68012-0208-11ea-9fd7-f2189899ab08: 5a:94:ef:e4:0c:ee
interfaces:
    qemu: unix:///tmp/qemu.sock
`,
		},
		{
			CaseName:    "Legacy from README: UML",
			Args:        []string{"-debug", "-listen", "unix:///tmp/network.sock", "-listen-bess", "unixpacket:///tmp/bess.sock"},
			InputConfig: "",
			ResultConfig: `listen:
    - unix:///tmp/network.sock
log-level: debug
stack:
    debug: true
    capture-file: capture.pcap
    mtu: 1500
    subnet: 192.168.127.0/24
    gatewayIP: 192.168.127.1
    gatewayMacAddress: 5a:94:ef:e4:0c:dd
    dns:
        - name: containers.internal.
          records:
            - name: gateway
              ip: 192.168.127.1
            - name: host
              ip: 192.168.127.254
        - name: docker.internal.
          records:
            - name: gateway
              ip: 192.168.127.1
            - name: host
              ip: 192.168.127.254
    forwards:
        127.0.0.1:2222: 192.168.127.2:22
    nat:
        192.168.127.254: 127.0.0.1
    gatewayVirtualIPs:
        - 192.168.127.254
    dhcpStaticLeases:
        192.168.127.2: 5a:94:ef:e4:0c:ee
    vpnKitUUIDMacAddresses:
        c3d68012-0208-11ea-9fd7-f2189899ab08: 5a:94:ef:e4:0c:ee
interfaces:
    bess: unixpacket:///tmp/bess.sock
`,
		},
		{
			CaseName:    "Legacy from README: VFKit",
			Args:        []string{"-debug", "-listen", "unix:///tmp/network.sock", "--listen-vfkit", "unixgram:///tmp/vfkit.sock"},
			InputConfig: "",
			ResultConfig: `listen:
    - unix:///tmp/network.sock
log-level: debug
stack:
    debug: true
    capture-file: capture.pcap
    mtu: 1500
    subnet: 192.168.127.0/24
    gatewayIP: 192.168.127.1
    gatewayMacAddress: 5a:94:ef:e4:0c:dd
    dns:
        - name: containers.internal.
          records:
            - name: gateway
              ip: 192.168.127.1
            - name: host
              ip: 192.168.127.254
        - name: docker.internal.
          records:
            - name: gateway
              ip: 192.168.127.1
            - name: host
              ip: 192.168.127.254
    forwards:
        127.0.0.1:2222: 192.168.127.2:22
    nat:
        192.168.127.254: 127.0.0.1
    gatewayVirtualIPs:
        - 192.168.127.254
    dhcpStaticLeases:
        192.168.127.2: 5a:94:ef:e4:0c:ee
    vpnKitUUIDMacAddresses:
        c3d68012-0208-11ea-9fd7-f2189899ab08: 5a:94:ef:e4:0c:ee
interfaces:
    vfkit: unixgram:///tmp/vfkit.sock
`,
		},
		{
			CaseName:    "Legacy from README: vsock",
			Args:        []string{"-debug", "-listen", "unix:///tmp/network.sock", "-listen-qemu", "unix:///tmp/qemu.sock"},
			InputConfig: "",
			ResultConfig: `listen:
    - unix:///tmp/network.sock
log-level: debug
stack:
    debug: true
    capture-file: capture.pcap
    mtu: 1500
    subnet: 192.168.127.0/24
    gatewayIP: 192.168.127.1
    gatewayMacAddress: 5a:94:ef:e4:0c:dd
    dns:
        - name: containers.internal.
          records:
            - name: gateway
              ip: 192.168.127.1
            - name: host
              ip: 192.168.127.254
        - name: docker.internal.
          records:
            - name: gateway
              ip: 192.168.127.1
            - name: host
              ip: 192.168.127.254
    forwards:
        127.0.0.1:2222: 192.168.127.2:22
    nat:
        192.168.127.254: 127.0.0.1
    gatewayVirtualIPs:
        - 192.168.127.254
    dhcpStaticLeases:
        192.168.127.2: 5a:94:ef:e4:0c:ee
    vpnKitUUIDMacAddresses:
        c3d68012-0208-11ea-9fd7-f2189899ab08: 5a:94:ef:e4:0c:ee
interfaces:
    qemu: unix:///tmp/qemu.sock
`,
		},
		{
			CaseName:    "config: empty config",
			Args:        []string{"-config", "config.yaml"},
			InputConfig: ``,
			ResultConfig: `log-level: info
stack:
    mtu: 1500
    subnet: 192.168.127.0/24
    gatewayIP: 192.168.127.1
    gatewayMacAddress: 5a:94:ef:e4:0c:dd
    nat:
        192.168.127.254: 127.0.0.1
    gatewayVirtualIPs:
        - 192.168.127.254
`,
		},
		{
			CaseName: "config: listen, loglevel, qemu",
			Args:     []string{"-config", "config.yaml"},
			InputConfig: `listen:
    - unix:///var/run/gvproxy/domain-2.sock
log-level: warning
interfaces:
    qemu: unix:///tmp/qemu.sock`,
			ResultConfig: `listen:
    - unix:///var/run/gvproxy/domain-2.sock
log-level: warning
stack:
    mtu: 1500
    subnet: 192.168.127.0/24
    gatewayIP: 192.168.127.1
    gatewayMacAddress: 5a:94:ef:e4:0c:dd
    nat:
        192.168.127.254: 127.0.0.1
    gatewayVirtualIPs:
        - 192.168.127.254
interfaces:
    qemu: unix:///tmp/qemu.sock
`,
		},
		{
			CaseName: "config: stack changes: auto addresses from subnet",
			Args:     []string{"-config", "config.yaml"},
			InputConfig: `listen:
    - unix:///var/run/gvproxy/domain-2.sock
log-level: warning
stack:
    mtu: 1480
    subnet: 10.0.0.0/16
    gatewayMacAddress: 10:11:11:11:11:00
`,
			ResultConfig: `listen:
    - unix:///var/run/gvproxy/domain-2.sock
log-level: warning
stack:
    mtu: 1480
    subnet: 10.0.0.0/16
    gatewayIP: 10.0.0.1
    gatewayMacAddress: "10:11:11:11:11:00"
    nat:
        10.0.255.254: 127.0.0.1
    gatewayVirtualIPs:
        - 10.0.255.254
`,
		},
		{
			CaseName: "config: stack changes: dhcpStaticLeases",
			Args:     []string{"-config", "config.yaml"},
			InputConfig: `stack:
    subnet: 10.0.0.0/16
    dhcpStaticLeases:
        10.0.0.2: "10:11:11:11:11:02"
        10.0.0.3: "10:11:11:11:11:03"
        10.0.0.100: "10:11:11:11:11:dd"
`,
			ResultConfig: `log-level: info
stack:
    mtu: 1500
    subnet: 10.0.0.0/16
    gatewayIP: 10.0.0.1
    gatewayMacAddress: 5a:94:ef:e4:0c:dd
    nat:
        10.0.255.254: 127.0.0.1
    gatewayVirtualIPs:
        - 10.0.255.254
    dhcpStaticLeases:
        10.0.0.2: "10:11:11:11:11:02"
        10.0.0.3: "10:11:11:11:11:03"
        10.0.0.100: 10:11:11:11:11:dd
`,
		},
		{
			CaseName: "config: stack changes: tcp forwards",
			Args:     []string{"-config", "config.yaml"},
			InputConfig: `stack:
    subnet: 10.0.0.0/16
    forwards:
        127.0.0.1:59022: 192.168.127.2:22
        127.0.0.1:59080: 192.168.127.2:80
        127.0.0.1:59443: 192.168.127.2:443
`,
			ResultConfig: `log-level: info
stack:
    mtu: 1500
    subnet: 10.0.0.0/16
    gatewayIP: 10.0.0.1
    gatewayMacAddress: 5a:94:ef:e4:0c:dd
    forwards:
        127.0.0.1:59022: 192.168.127.2:22
        127.0.0.1:59080: 192.168.127.2:80
        127.0.0.1:59443: 192.168.127.2:443
    nat:
        10.0.255.254: 127.0.0.1
    gatewayVirtualIPs:
        - 10.0.255.254
`,
		},
		{
			CaseName: "config: ssh forwards fails on identity file missing",
			Args:     []string{"-config", "config.yaml"},
			InputConfig: `stack:
    subnet: 10.0.0.0/16
forwards:
    - socket: ???
      dest: ???
      user: ???
      identity: ???
`,
			ResultConfig: `log-level: info
stack:
    mtu: 1500
    subnet: 10.0.0.0/16
    gatewayIP: 10.0.0.1
    gatewayMacAddress: 5a:94:ef:e4:0c:dd
    nat:
        10.0.255.254: 127.0.0.1
    gatewayVirtualIPs:
        - 10.0.255.254
forwards:
    - socket: ???
      dest: ???
      user: ???
      identity: ???
`,
			Error: errors.New(""),
		},
		{
			CaseName:    "debug check #1",
			Args:        []string{"-config", "config.yaml"},
			InputConfig: `log-level: debug`,
			ResultConfig: `log-level: debug
stack:
    debug: true
    mtu: 1500
    subnet: 192.168.127.0/24
    gatewayIP: 192.168.127.1
    gatewayMacAddress: 5a:94:ef:e4:0c:dd
    nat:
        192.168.127.254: 127.0.0.1
    gatewayVirtualIPs:
        - 192.168.127.254
`,
		},
		{
			CaseName:    "debug check #2",
			Args:        []string{"-debug", "-config", "config.yaml"},
			InputConfig: `log-level: error`,
			ResultConfig: `log-level: debug
stack:
    debug: true
    mtu: 1500
    subnet: 192.168.127.0/24
    gatewayIP: 192.168.127.1
    gatewayMacAddress: 5a:94:ef:e4:0c:dd
    nat:
        192.168.127.254: 127.0.0.1
    gatewayVirtualIPs:
        - 192.168.127.254
`,
		},
		{
			CaseName:    "debug check #3",
			Args:        []string{"-debug"},
			InputConfig: "",
			ResultConfig: `log-level: debug
stack:
    debug: true
    capture-file: capture.pcap
    mtu: 1500
    subnet: 192.168.127.0/24
    gatewayIP: 192.168.127.1
    gatewayMacAddress: 5a:94:ef:e4:0c:dd
    dns:
        - name: containers.internal.
          records:
            - name: gateway
              ip: 192.168.127.1
            - name: host
              ip: 192.168.127.254
        - name: docker.internal.
          records:
            - name: gateway
              ip: 192.168.127.1
            - name: host
              ip: 192.168.127.254
    forwards:
        127.0.0.1:2222: 192.168.127.2:22
    nat:
        192.168.127.254: 127.0.0.1
    gatewayVirtualIPs:
        - 192.168.127.254
    dhcpStaticLeases:
        192.168.127.2: 5a:94:ef:e4:0c:ee
    vpnKitUUIDMacAddresses:
        c3d68012-0208-11ea-9fd7-f2189899ab08: 5a:94:ef:e4:0c:ee
`,
		},
	}
}
