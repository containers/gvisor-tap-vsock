package dns

import (
	"net"
	"testing"

	"github.com/containers/gvisor-tap-vsock/pkg/types"
	"github.com/onsi/ginkgo"
	"github.com/onsi/gomega"
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
})
