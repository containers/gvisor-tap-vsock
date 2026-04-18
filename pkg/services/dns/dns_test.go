package dns

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/containers/gvisor-tap-vsock/pkg/types"
	"github.com/foxcpp/go-mockdns"
	"github.com/miekg/dns"
	"github.com/onsi/ginkgo"
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

	var _ = ginkgo.Describe("dns remove test", func() {
		ginkgo.It("should remove zone by name and remove records and defaultIP", func() {
			zone := types.Zone{
				Name:      "internal.",
				DefaultIP: net.ParseIP("192.168.0.1"),
				Records: []types.Record{{
					Name: "host",
					IP:   net.ParseIP("192.168.0.2"),
				}},
			}
			server, _ = New(nil, nil, []types.Zone{zone})
			gomega.Expect(server.removeZone("internal.")).To(gomega.BeTrue())
			gomega.Expect(server.handler.zones).To(gomega.BeEmpty())
		})

		ginkgo.It("removeZone returns false when zone does not exist", func() {
			server, _ = New(nil, nil, []types.Zone{{
				Name:      "internal.",
				DefaultIP: net.ParseIP("192.168.0.1"),
			}})
			gomega.Expect(server.removeZone("other.")).To(gomega.BeFalse())
			gomega.Expect(server.handler.zones).To(gomega.HaveLen(1))
			gomega.Expect(server.handler.zones[0].Name).To(gomega.Equal("internal."))
		})

		ginkgo.It("should not affect other zones when removing one", func() {
			zone1 := types.Zone{Name: "first.", DefaultIP: net.ParseIP("192.168.0.1")}
			zone2 := types.Zone{Name: "second.", DefaultIP: net.ParseIP("192.168.0.2")}
			zone3 := types.Zone{Name: "third.", DefaultIP: net.ParseIP("192.168.0.3")}
			server, _ = New(nil, nil, []types.Zone{zone1, zone2, zone3})
			gomega.Expect(server.removeZone("second.")).To(gomega.BeTrue())
			gomega.Expect(server.handler.zones).To(gomega.Equal([]types.Zone{zone1, zone3}))
		})

		ginkgo.It("removeZone returns false when zones are empty", func() {
			server, _ = New(nil, nil, []types.Zone{})
			gomega.Expect(server.removeZone("internal.")).To(gomega.BeFalse())
		})
	})

	var _ = ginkgo.Describe("dns Mux /remove handler", func() {
		ginkgo.It("POST /remove with name removes zone and returns 200", func() {
			zone := types.Zone{
				Name:      "dynamic.internal.",
				DefaultIP: net.ParseIP("192.168.0.1"),
				Records:   []types.Record{{Name: "host", IP: net.ParseIP("192.168.0.2")}},
			}
			server, _ = New(nil, nil, []types.Zone{zone})
			body, _ := json.Marshal(types.Zone{Name: "dynamic.internal."})
			req := httptest.NewRequest(http.MethodPost, "/remove", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()
			server.Mux().ServeHTTP(rec, req)
			gomega.Expect(rec.Code).To(gomega.Equal(http.StatusOK))
			gomega.Expect(server.handler.zones).To(gomega.BeEmpty())
		})

		ginkgo.It("POST /remove with non-existent zone returns 404", func() {
			server, _ = New(nil, nil, []types.Zone{{
				Name:      "internal.",
				DefaultIP: net.ParseIP("192.168.0.1"),
			}})
			body, _ := json.Marshal(types.Zone{Name: "other."})
			req := httptest.NewRequest(http.MethodPost, "/remove", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()
			server.Mux().ServeHTTP(rec, req)
			gomega.Expect(rec.Code).To(gomega.Equal(http.StatusNotFound))
			gomega.Expect(server.handler.zones).To(gomega.HaveLen(1))
		})

		ginkgo.It("POST /remove with empty name returns 400", func() {
			server, _ = New(nil, nil, []types.Zone{})
			body, _ := json.Marshal(types.Zone{Name: ""})
			req := httptest.NewRequest(http.MethodPost, "/remove", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()
			server.Mux().ServeHTTP(rec, req)
			gomega.Expect(rec.Code).To(gomega.Equal(http.StatusBadRequest))
		})

		ginkgo.It("GET /remove returns 400", func() {
			server, _ = New(nil, nil, []types.Zone{})
			req := httptest.NewRequest(http.MethodGet, "/remove", nil)
			rec := httptest.NewRecorder()
			server.Mux().ServeHTTP(rec, req)
			gomega.Expect(rec.Code).To(gomega.Equal(http.StatusBadRequest))
		})
	})

	var _ = ginkgo.Describe("dns removeRecord test", func() {
		ginkgo.It("should remove matching record from zone by name and IP", func() {
			zone := types.Zone{
				Name: "internal.",
				Records: []types.Record{
					{Name: "host1", IP: net.ParseIP("192.168.0.2")},
					{Name: "host2", IP: net.ParseIP("192.168.0.3")},
				},
			}
			server, _ = New(nil, nil, []types.Zone{zone})
			err := server.removeRecord(removeRecordRequest{Name: "internal.", Record: types.Record{Name: "host1", IP: net.ParseIP("192.168.0.2")}})
			gomega.Expect(err).To(gomega.BeNil())
			gomega.Expect(server.handler.zones).To(gomega.Equal([]types.Zone{{
				Name: "internal.",
				Records: []types.Record{
					{Name: "host2", IP: net.ParseIP("192.168.0.3")},
				},
			}}))
		})

		ginkgo.It("should remove all records matching record name when IP not specified", func() {
			zone := types.Zone{
				Name: "internal.",
				Records: []types.Record{
					{Name: "host", IP: net.ParseIP("192.168.0.2")},
					{Name: "host", IP: net.ParseIP("192.168.0.3")},
					{Name: "other", IP: net.ParseIP("192.168.0.4")},
				},
			}
			server, _ = New(nil, nil, []types.Zone{zone})
			err := server.removeRecord(removeRecordRequest{Name: "internal.", Record: types.Record{Name: "host"}})
			gomega.Expect(err).To(gomega.BeNil())
			gomega.Expect(server.handler.zones[0].Records).To(gomega.Equal([]types.Record{
				{Name: "other", IP: net.ParseIP("192.168.0.4")},
			}))
		})

		ginkgo.It("removeRecord returns error when zone does not exist", func() {
			server, _ = New(nil, nil, []types.Zone{{
				Name:    "internal.",
				Records: []types.Record{{Name: "host", IP: net.ParseIP("192.168.0.2")}},
			}})
			err := server.removeRecord(removeRecordRequest{Name: "other.", Record: types.Record{Name: "host", IP: net.ParseIP("192.168.0.2")}})
			gomega.Expect(err).To(gomega.MatchError("zone not found"))
			gomega.Expect(server.handler.zones[0].Records).To(gomega.HaveLen(1))
		})

		ginkgo.It("removeRecord returns error when no record matches", func() {
			zone := types.Zone{
				Name:    "internal.",
				Records: []types.Record{{Name: "host", IP: net.ParseIP("192.168.0.2")}},
			}
			server, _ = New(nil, nil, []types.Zone{zone})
			err := server.removeRecord(removeRecordRequest{Name: "internal.", Record: types.Record{Name: "host", IP: net.ParseIP("192.168.0.99")}})
			gomega.Expect(err).To(gomega.MatchError("record not found"))
			gomega.Expect(server.handler.zones[0].Records).To(gomega.HaveLen(1))
		})

		ginkgo.It("removeRecord returns error when zone name is empty", func() {
			server, _ = New(nil, nil, []types.Zone{})
			err := server.removeRecord(removeRecordRequest{Name: "", Record: types.Record{Name: "host"}})
			gomega.Expect(err).To(gomega.MatchError("name is required"))
		})

		ginkgo.It("removeRecord returns error when record name is empty", func() {
			server, _ = New(nil, nil, []types.Zone{{Name: "internal.", Records: nil}})
			err := server.removeRecord(removeRecordRequest{Name: "internal.", Record: types.Record{Name: ""}})
			gomega.Expect(err).To(gomega.MatchError("record name is required"))
		})
	})

	var _ = ginkgo.Describe("dns Mux /remove/record handler", func() {
		ginkgo.It("POST /remove/record with name and record removes record and returns 200", func() {
			zone := types.Zone{
				Name: "internal.",
				Records: []types.Record{
					{Name: "host", IP: net.ParseIP("192.168.0.2")},
					{Name: "gateway", IP: net.ParseIP("192.168.0.1")},
				},
			}
			server, _ = New(nil, nil, []types.Zone{zone})
			body, _ := json.Marshal(removeRecordRequest{
				Name:   "internal.",
				Record: types.Record{Name: "host", IP: net.ParseIP("192.168.0.2")},
			})
			req := httptest.NewRequest(http.MethodPost, "/remove/record", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()
			server.Mux().ServeHTTP(rec, req)
			gomega.Expect(rec.Code).To(gomega.Equal(http.StatusOK))
			gomega.Expect(server.handler.zones[0].Records).To(gomega.Equal([]types.Record{
				{Name: "gateway", IP: net.ParseIP("192.168.0.1")},
			}))
		})

		ginkgo.It("POST /remove/record with non-existent zone returns 400", func() {
			server, _ = New(nil, nil, []types.Zone{{
				Name:    "internal.",
				Records: []types.Record{{Name: "host", IP: net.ParseIP("192.168.0.2")}},
			}})
			body, _ := json.Marshal(removeRecordRequest{
				Name:   "other.",
				Record: types.Record{Name: "host", IP: net.ParseIP("192.168.0.2")},
			})
			req := httptest.NewRequest(http.MethodPost, "/remove/record", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()
			server.Mux().ServeHTTP(rec, req)
			gomega.Expect(rec.Code).To(gomega.Equal(http.StatusBadRequest))
			gomega.Expect(rec.Body.String()).To(gomega.ContainSubstring("zone not found"))
		})

		ginkgo.It("POST /remove/record with non-existent record returns 400", func() {
			server, _ = New(nil, nil, []types.Zone{{
				Name:    "internal.",
				Records: []types.Record{{Name: "host", IP: net.ParseIP("192.168.0.2")}},
			}})
			body, _ := json.Marshal(removeRecordRequest{
				Name:   "internal.",
				Record: types.Record{Name: "missing", IP: net.ParseIP("192.168.0.99")},
			})
			req := httptest.NewRequest(http.MethodPost, "/remove/record", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()
			server.Mux().ServeHTTP(rec, req)
			gomega.Expect(rec.Code).To(gomega.Equal(http.StatusBadRequest))
			gomega.Expect(rec.Body.String()).To(gomega.ContainSubstring("record not found"))
		})

		ginkgo.It("POST /remove/record with empty zone name returns 400", func() {
			server, _ = New(nil, nil, []types.Zone{})
			body, _ := json.Marshal(removeRecordRequest{Name: "", Record: types.Record{Name: "host"}})
			req := httptest.NewRequest(http.MethodPost, "/remove/record", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()
			server.Mux().ServeHTTP(rec, req)
			gomega.Expect(rec.Code).To(gomega.Equal(http.StatusBadRequest))
		})

		ginkgo.It("POST /remove/record with empty record name returns 400", func() {
			server, _ = New(nil, nil, []types.Zone{})
			body, _ := json.Marshal(removeRecordRequest{Name: "internal.", Record: types.Record{Name: ""}})
			req := httptest.NewRequest(http.MethodPost, "/remove/record", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()
			server.Mux().ServeHTTP(rec, req)
			gomega.Expect(rec.Code).To(gomega.Equal(http.StatusBadRequest))
		})

		ginkgo.It("GET /remove/record returns 400", func() {
			server, _ = New(nil, nil, []types.Zone{})
			req := httptest.NewRequest(http.MethodGet, "/remove/record", nil)
			rec := httptest.NewRecorder()
			server.Mux().ServeHTTP(rec, req)
			gomega.Expect(rec.Code).To(gomega.Equal(http.StatusBadRequest))
		})
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
