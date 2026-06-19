package dns

import (
	"context"
	"net"
	"regexp"
	"testing"
	"time"

	"github.com/containers/gvisor-tap-vsock/pkg/types"
	"github.com/foxcpp/go-mockdns"
	"github.com/miekg/dns"
	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

func TestSuite(t *testing.T) {
	gomega.RegisterFailHandler(ginkgo.Fail)
	ginkgo.RunSpecs(t, "gvisor-tap-vsock dns suit")
}

var _ = ginkgo.Describe("dns add test", func() {
	var server *Server

	ginkgo.BeforeEach(func() {
		server, _ = New(nil, nil, []types.Zone{})
	})

	ginkgo.It("should add dns zone with ip", func() {
		req := types.Zone{
			Name:      "internal.",
			DefaultIP: net.ParseIP("192.168.0.1"),
		}
		server.addZone(req)

		gomega.Expect(server.handler.zones).To(gomega.Equal([]types.Zone{req}))
	})

	ginkgo.It("should add dns zone with record", func() {
		req := types.Zone{
			Name: "internal.",
			Records: []types.Record{{
				Name: "crc.testiing",
				IP:   net.ParseIP("192.168.0.2"),
			}},
		}
		server.addZone(req)

		gomega.Expect(server.handler.zones).To(gomega.Equal([]types.Zone{req}))
	})

	ginkgo.It("should add dns zone with record and ip", func() {
		ipReq := types.Zone{
			Name:      "dynamic.internal.",
			DefaultIP: net.ParseIP("192.168.0.1"),
		}
		recordReq := types.Zone{
			Name: "internal.",
			Records: []types.Record{{
				Name: "crc.testiing",
				IP:   net.ParseIP("192.168.0.2"),
			}},
		}
		server.addZone(ipReq)
		server.addZone(recordReq)

		gomega.Expect(server.handler.zones).To(gomega.Equal([]types.Zone{ipReq, recordReq}))
	})

	ginkgo.It("should add new zone to existing zone with default ip", func() {
		ipReq := types.Zone{
			Name:      "internal.",
			DefaultIP: net.ParseIP("192.168.0.1"),
		}
		server.addZone(ipReq)
		recordReq := types.Zone{
			Name: "internal.",
			Records: []types.Record{{
				Name: "crc.testing",
				IP:   net.ParseIP("192.168.0.2"),
			}},
		}
		server.addZone(recordReq)

		gomega.Expect(server.handler.zones).To(gomega.Equal([]types.Zone{{
			Name: "internal.",
			Records: []types.Record{{
				Name: "crc.testing",
				IP:   net.ParseIP("192.168.0.2"),
			}},
		}}))
	})

	ginkgo.It("should add new zone to existing zone with records", func() {
		ipReq := types.Zone{
			Name: "internal.",
			Records: []types.Record{{
				Name: "crc.testing",
				IP:   net.ParseIP("192.168.0.2"),
			}},
		}
		server.addZone(ipReq)
		recordReq := types.Zone{
			Name: "internal.",
			Records: []types.Record{{
				Name: "crc.testing",
				IP:   net.ParseIP("192.168.0.3"),
			}},
		}
		server.addZone(recordReq)

		gomega.Expect(server.handler.zones).To(gomega.Equal([]types.Zone{{
			Name: "internal.",
			Records: []types.Record{{
				Name: "crc.testing",
				IP:   net.ParseIP("192.168.0.3"),
			}, {
				Name: "crc.testing",
				IP:   net.ParseIP("192.168.0.2"),
			}},
		}}))
	})

	ginkgo.It("should add new zone to existing zone with records", func() {
		ipReq := types.Zone{
			Name: "internal.",
			Records: []types.Record{{
				Name: "crc.testing",
				IP:   net.ParseIP("192.168.0.2"),
			}},
		}
		server.addZone(ipReq)
		recordReq := types.Zone{
			Name: "internal.",
			Records: []types.Record{{
				Name: "crc.testing",
				IP:   net.ParseIP("192.168.0.3"),
			}},
		}
		server.addZone(recordReq)

		gomega.Expect(server.handler.zones).To(gomega.Equal([]types.Zone{{
			Name: "internal.",
			Records: []types.Record{{
				Name: "crc.testing",
				IP:   net.ParseIP("192.168.0.3"),
			}, {
				Name: "crc.testing",
				IP:   net.ParseIP("192.168.0.2"),
			}},
		}}))
	})

	ginkgo.It("should retain the order of zones", func() {
		server, _ = New(nil, nil, []types.Zone{
			{
				Name:      "crc.testing.",
				DefaultIP: net.ParseIP("192.168.127.2"),
			},
			{
				Name: "testing.",
				Records: []types.Record{
					{
						Name: "host",
						IP:   net.ParseIP("192.168.127.3"),
					},
				},
			},
		})
		server.addZone(types.Zone{
			Name: "testing.",
			Records: []types.Record{
				{
					Name: "gateway",
					IP:   net.ParseIP("192.168.127.1"),
				},
			},
		})
		gomega.Expect(server.handler.zones).To(gomega.Equal([]types.Zone{
			{
				Name:      "crc.testing.",
				DefaultIP: net.ParseIP("192.168.127.2"),
			},
			{
				Name: "testing.",
				Records: []types.Record{
					{
						Name: "gateway",
						IP:   net.ParseIP("192.168.127.1"),
					},
					{
						Name: "host",
						IP:   net.ParseIP("192.168.127.3"),
					},
				},
			},
		}))
	})

	ginkgo.It("Should pass DNS requests to default system DNS server", func() {
		m := &dns.Msg{
			MsgHdr: dns.MsgHdr{
				Authoritative:     false,
				AuthenticatedData: false,
				CheckingDisabled:  false,
				RecursionDesired:  true,
				Opcode:            0,
			},
			Question: make([]dns.Question, 1),
		}

		m.Question[0] = dns.Question{
			Name:   "redhat.com.",
			Qtype:  1,
			Qclass: 1,
		}

		server.handler.addAnswers(m)

		gomega.Expect(m.Answer[0].Header().Name).To(gomega.Equal("redhat.com."))
		gomega.Expect(m.Answer[0].String()).To(gomega.SatisfyAny(gomega.ContainSubstring("34.235.198.240"), gomega.ContainSubstring("52.200.142.250")))
	})

	ginkgo.It("should match existing zones case-insensitively", func() {
		server.addZone(types.Zone{
			Name:      "internal.",
			DefaultIP: net.ParseIP("192.168.0.1"),
		})
		server.addZone(types.Zone{
			Name: "Internal.",
			Records: []types.Record{{
				Name: "api",
				IP:   net.ParseIP("192.168.0.2"),
			}},
		})
		gomega.Expect(server.handler.zones).To(gomega.HaveLen(1))
		gomega.Expect(server.handler.zones[0].Name).To(gomega.Equal("internal."))
	})

	ginkgo.It("should preserve Protected flag when merging into existing zone", func() {
		server, _ = New(nil, nil, []types.Zone{
			{Name: "system.internal.", Protected: true, DefaultIP: net.ParseIP("10.0.0.1")},
		})
		server.addZone(types.Zone{
			Name:    "system.internal.",
			Records: []types.Record{{Name: "api", IP: net.ParseIP("10.0.0.2")}},
		})
		gomega.Expect(server.handler.zones[0].Protected).To(gomega.BeTrue())
	})

	ginkgo.It("should set Protected to false for newly added zones", func() {
		server.addZone(types.Zone{
			Name:      "sneaky.zone.",
			Protected: true,
			DefaultIP: net.ParseIP("10.0.0.1"),
		})
		gomega.Expect(server.handler.zones[0].Protected).To(gomega.BeFalse())
	})

})

var _ = ginkgo.Describe("dns zone validation", func() {
	var server *Server

	ginkgo.BeforeEach(func() {
		server, _ = New(nil, nil, []types.Zone{
			{
				Name:      "containers.internal.",
				Protected: true,
				DefaultIP: net.ParseIP("192.168.127.1"),
			},
			{
				Name:      "docker.internal.",
				Protected: true,
				DefaultIP: net.ParseIP("192.168.127.1"),
			},
		})
	})

	ginkgo.It("should reject empty zone name", func() {
		err := server.validateZone(types.Zone{Name: ""})
		gomega.Expect(err).To(gomega.HaveOccurred())
		gomega.Expect(err.Error()).To(gomega.ContainSubstring("zone name is required"))
	})

	ginkgo.It("should reject zone name without trailing dot", func() {
		err := server.validateZone(types.Zone{Name: "example.com"})
		gomega.Expect(err).To(gomega.HaveOccurred())
		gomega.Expect(err.Error()).To(gomega.ContainSubstring("fully qualified"))
	})

	ginkgo.It("should reject zone name with invalid characters", func() {
		err := server.validateZone(types.Zone{Name: "my zone!.local."})
		gomega.Expect(err).To(gomega.HaveOccurred())
		gomega.Expect(err.Error()).To(gomega.ContainSubstring("invalid characters"))
	})

	ginkgo.It("should reject zone name with path traversal characters", func() {
		err := server.validateZone(types.Zone{Name: "../etc/passwd."})
		gomega.Expect(err).To(gomega.HaveOccurred())
		gomega.Expect(err.Error()).To(gomega.ContainSubstring("invalid DNS zone name"))
	})

	ginkgo.It("should reject root zone", func() {
		err := server.validateZone(types.Zone{
			Name:      ".",
			DefaultIP: net.ParseIP("1.2.3.4"),
		})
		gomega.Expect(err).To(gomega.HaveOccurred())
		gomega.Expect(err.Error()).To(gomega.ContainSubstring("root zone"))
	})

	ginkgo.It("should reject overwriting protected zone containers.internal.", func() {
		err := server.validateZone(types.Zone{
			Name:      "containers.internal.",
			DefaultIP: net.ParseIP("1.2.3.4"),
		})
		gomega.Expect(err).To(gomega.HaveOccurred())
		gomega.Expect(err.Error()).To(gomega.ContainSubstring("protected zone"))
	})

	ginkgo.It("should reject overwriting protected zone docker.internal.", func() {
		err := server.validateZone(types.Zone{
			Name:      "docker.internal.",
			DefaultIP: net.ParseIP("1.2.3.4"),
		})
		gomega.Expect(err).To(gomega.HaveOccurred())
		gomega.Expect(err.Error()).To(gomega.ContainSubstring("protected zone"))
	})

	ginkgo.It("should reject protected zone case-insensitively", func() {
		err := server.validateZone(types.Zone{
			Name:      "Docker.Internal.",
			DefaultIP: net.ParseIP("1.2.3.4"),
		})
		gomega.Expect(err).To(gomega.HaveOccurred())
		gomega.Expect(err.Error()).To(gomega.ContainSubstring("protected zone"))
	})

	ginkgo.It("should reject zone with no records and no default IP", func() {
		err := server.validateZone(types.Zone{Name: "blackhole.local."})
		gomega.Expect(err).To(gomega.HaveOccurred())
		gomega.Expect(err.Error()).To(gomega.ContainSubstring("at least one record or a default IP"))
	})

	ginkgo.It("should reject zone with unspecified default IP and no records", func() {
		err := server.validateZone(types.Zone{
			Name:      "test.local.",
			DefaultIP: net.ParseIP("0.0.0.0"),
		})
		gomega.Expect(err).To(gomega.HaveOccurred())
		gomega.Expect(err.Error()).To(gomega.ContainSubstring("at least one record or a default IP"))
	})

	ginkgo.It("should reject record name with invalid characters", func() {
		err := server.validateZone(types.Zone{
			Name: "myapp.local.",
			Records: []types.Record{
				{Name: "../../etc/passwd", IP: net.ParseIP("10.0.0.1")},
			},
		})
		gomega.Expect(err).To(gomega.HaveOccurred())
		gomega.Expect(err.Error()).To(gomega.ContainSubstring("invalid characters"))
	})

	ginkgo.It("should accept record name with underscores", func() {
		err := server.validateZone(types.Zone{
			Name: "myapp.local.",
			Records: []types.Record{
				{Name: "_sip._tcp", IP: net.ParseIP("10.0.0.1")},
			},
		})
		gomega.Expect(err).ToNot(gomega.HaveOccurred())
	})

	ginkgo.It("should reject record with empty name", func() {
		err := server.validateZone(types.Zone{
			Name: "myapp.local.",
			Records: []types.Record{
				{Name: "", IP: net.ParseIP("10.0.0.1")},
			},
		})
		gomega.Expect(err).To(gomega.HaveOccurred())
		gomega.Expect(err.Error()).To(gomega.ContainSubstring("record name is required"))
	})

	ginkgo.It("should reject record without IP or regexp", func() {
		err := server.validateZone(types.Zone{
			Name: "myapp.local.",
			Records: []types.Record{
				{Name: "api"},
			},
		})
		gomega.Expect(err).To(gomega.HaveOccurred())
		gomega.Expect(err.Error()).To(gomega.ContainSubstring("must have an IP or regexp"))
	})

	ginkgo.It("should accept valid custom zone", func() {
		err := server.validateZone(types.Zone{
			Name:      "myapp.local.",
			DefaultIP: net.ParseIP("10.0.0.1"),
		})
		gomega.Expect(err).ToNot(gomega.HaveOccurred())
	})

	ginkgo.It("should accept valid zone with records", func() {
		err := server.validateZone(types.Zone{
			Name: "myapp.local.",
			Records: []types.Record{
				{Name: "api", IP: net.ParseIP("10.0.0.1")},
				{Name: "web", IP: net.ParseIP("10.0.0.2")},
			},
		})
		gomega.Expect(err).ToNot(gomega.HaveOccurred())
	})

	ginkgo.It("should accept zone with no records and only default IP", func() {
		err := server.validateZone(types.Zone{
			Name:      "wildcard.local.",
			DefaultIP: net.ParseIP("10.0.0.1"),
		})
		gomega.Expect(err).ToNot(gomega.HaveOccurred())
	})

	ginkgo.It("should accept record with regexp and no IP", func() {
		err := server.validateZone(types.Zone{
			Name: "myapp.local.",
			Records: []types.Record{
				{Name: "wildcard", Regexp: regexp.MustCompile(".*")},
			},
		})
		gomega.Expect(err).ToNot(gomega.HaveOccurred())
	})

	ginkgo.It("should accept zone name with hyphens", func() {
		err := server.validateZone(types.Zone{
			Name:      "my-app.local.",
			DefaultIP: net.ParseIP("10.0.0.1"),
		})
		gomega.Expect(err).ToNot(gomega.HaveOccurred())
	})

	ginkgo.It("should not protect zones that were not in the initial configuration", func() {
		err := server.validateZone(types.Zone{
			Name:      "custom.zone.",
			DefaultIP: net.ParseIP("10.0.0.1"),
		})
		gomega.Expect(err).ToNot(gomega.HaveOccurred())
	})
})

var _ = ginkgo.Describe("TXT records", func() {

	var cleanup func()
	var vsockResolver *net.Resolver
	var upstream upstreamResolver

	const longTxtDomain = "long.txt.test."         // 20230601._domainkey.gmail.com
	const multipleTxtDomain = "multiple.txt.test." // google.com

	ginkgo.BeforeEach(func() {
		var nameserver string
		var err error

		const txt = "abcdefghijklmnopqrstuvwxyz012456789"
		const longTxt = txt + txt + txt + txt + txt + txt + txt + txt
		upstream = &mockdns.Resolver{
			Zones: map[string]mockdns.Zone{
				longTxtDomain: {
					TXT: []string{longTxt},
				},
				multipleTxtDomain: {
					TXT: []string{"AAAAAAA", "BBBBBBB"},
				},
			},
		}

		nameserver, cleanup, err = startDNSServer(upstream)
		gomega.Expect(err).To(gomega.BeNil())
		time.Sleep(100 * time.Millisecond)

		vsockResolver = &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
				d := net.Dialer{}
				return d.DialContext(ctx, network, nameserver)
			},
		}
	})

	ginkgo.AfterEach(func() {
		if cleanup != nil {
			cleanup()
			// TODO port conflict race condition.
			time.Sleep(100 * time.Millisecond)
		}
	})

	ginkgo.When("There are long TXT Records", func() {

		hasLongString := func(records []string) bool {
			for _, txt := range records {
				if len(txt) > 255 {
					return true
				}
			}
			return false
		}
		ginkgo.It("Should produce the same result as upstream Resolver", func() {

			upstreamRecords, err := upstream.LookupTXT(context.Background(), longTxtDomain)
			gomega.Expect(err).To(gomega.BeNil())
			gomega.Expect(hasLongString(upstreamRecords)).To(gomega.BeTrue(), "Expected at least one TXT string longer than 255 bytes")

			vsockRecords, err := vsockResolver.LookupTXT(context.Background(), longTxtDomain)
			gomega.Expect(err).To(gomega.BeNil())

			gomega.Expect(vsockRecords).To(gomega.Equal(upstreamRecords))

		})

	})

	ginkgo.When("there are multiple TXT Records", func() {
		ginkgo.It("Should produce the same result as upstream Resolver", func() {
			upstreamRecords, err := upstream.LookupTXT(context.Background(), multipleTxtDomain)
			gomega.Expect(err).To(gomega.BeNil())
			gomega.Expect(len(upstreamRecords)).To(gomega.BeNumerically(">", 1), "Expected more than one TXT record")

			vsockRecords, err := vsockResolver.LookupTXT(context.Background(), multipleTxtDomain)
			gomega.Expect(err).To(gomega.BeNil())

			gomega.Expect(vsockRecords).To(gomega.ConsistOf(upstreamRecords))

		})
	})

})

type ARecord struct {
	name        string
	expectedIPs []string
}

func TestDNS(t *testing.T) {
	log.Infof("starting test DNS servers")

	upstream := &mockdns.Resolver{
		Zones: map[string]mockdns.Zone{
			"redhat.com.": {
				A: []string{"52.200.142.250", "34.235.198.240"},
			},
		},
	}

	nameserver, cleanup, err := startDNSServer(upstream)
	require.NoError(t, err)
	defer cleanup()
	time.Sleep(100 * time.Millisecond)
	log.Infof("test DNS servers started")

	r := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			d := net.Dialer{
				Timeout: time.Millisecond * time.Duration(10000),
			}
			log.Infof("dialing %s %s", network, nameserver)

			return d.DialContext(ctx, network, nameserver)
		},
	}
	redhatdotcom := ARecord{
		name:        "redhat.com",
		expectedIPs: []string{"52.200.142.250"},
	}
	record := redhatdotcom
	{
		log.Infof("looking up %s", record.name)
		ipGvisor, err := r.LookupHost(context.Background(), record.name)
		require.NoError(t, err)
		require.Subset(t, ipGvisor, record.expectedIPs)
		log.Infof("ip gvisor: %+v", ipGvisor)

		ipGo, err := net.LookupHost(record.name)
		require.NoError(t, err)
		log.Infof("ip go: %+v", ipGo)
		require.Subset(t, ipGvisor, ipGo)
	}
}

func startDNSServer(upstream upstreamResolver) (string, func(), error) {
	udpConn, err := net.ListenPacket("udp", "127.0.0.1:5354")
	if err != nil {
		return "", nil, err
	}

	tcpLn, err := net.Listen("tcp", "127.0.0.1:5354")
	if err != nil {
		return "", nil, err
	}

	server, err := NewWithUpstreamResolver(udpConn, tcpLn, nil, upstream)
	if err != nil {
		return "", nil, err
	}

	go func() {
		if err := server.Serve(); err != nil {
			log.Errorf("serve UDP error: %T %s", err, err)
		}
	}()
	go func() {
		if err := server.ServeTCP(); err != nil {
			log.Errorf("serve TCP error: %T %s", err, err)
		}
	}()
	return "127.0.0.1:5354", func() {
		udpConn.Close()
		tcpLn.Close()
	}, nil
}
