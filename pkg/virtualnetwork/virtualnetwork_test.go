package virtualnetwork

import (
	"strconv"
	"testing"
	"time"

	"github.com/containers/gvisor-tap-vsock/pkg/types"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/link/loopback"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
)

func TestCreateStackTCPTimeWaitTimeout(t *testing.T) {
	type testCase struct {
		name    string
		timeout int
		want    time.Duration
		wantErr bool
	}
	tests := []testCase{
		{name: "default", want: tcp.DefaultTCPTimeWaitTimeout},
		{name: "configured", timeout: 1, want: time.Second},
		{name: "negative", timeout: -1, wantErr: true},
	}
	if strconv.IntSize == 64 {
		timeoutTooLarge := int64((1<<63-1)/int64(time.Second)) + 1
		tests = append(tests, testCase{name: "too large", timeout: int(timeoutTooLarge), wantErr: true})
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			configuration := &types.Configuration{
				GatewayIP:          "192.168.127.1",
				Subnet:             "192.168.127.0/24",
				TCPTimeWaitTimeout: test.timeout,
			}
			s, err := createStack(configuration, loopback.New())
			if test.wantErr {
				if err == nil {
					t.Fatal("createStack succeeded, want error")
				}
				return
			}
			if err != nil {
				t.Fatalf("createStack: %v", err)
			}

			var got tcpip.TCPTimeWaitTimeoutOption
			if err := s.TransportProtocolOption(tcp.ProtocolNumber, &got); err != nil {
				t.Fatalf("TransportProtocolOption: %v", err)
			}
			if got != tcpip.TCPTimeWaitTimeoutOption(test.want) {
				t.Fatalf("TCP time-wait timeout = %s, want %s", time.Duration(got), test.want)
			}
		})
	}
}
