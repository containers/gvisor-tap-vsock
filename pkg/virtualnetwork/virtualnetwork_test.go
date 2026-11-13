package virtualnetwork

import (
	"os"
	"path/filepath"
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
		timeout *int
		want    time.Duration
		wantErr bool
	}
	tests := []testCase{
		{name: "default", want: tcp.DefaultTCPTimeWaitTimeout},
		{name: "zero", timeout: intPtr(0), want: 0},
		{name: "configured", timeout: intPtr(1), want: time.Second},
		{name: "negative", timeout: intPtr(-1), wantErr: true},
	}
	if strconv.IntSize == 64 {
		timeoutTooLarge := int64((1<<63-1)/int64(time.Second)) + 1
		tests = append(tests, testCase{name: "too large", timeout: intPtr(int(timeoutTooLarge)), wantErr: true})
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			configuration := &types.Configuration{
				GatewayIP:          "192.168.127.1",
				Subnet:             "192.168.127.0/24",
				TCPTimeWaitTimeout: test.timeout,
			}
			var timeout *time.Duration
			if test.timeout != nil {
				parsed, err := parseTCPTimeWaitTimeout(*test.timeout)
				if test.wantErr {
					if err == nil {
						t.Fatal("expected invalid timeout error")
					}
					return
				}
				if err != nil {
					t.Fatal(err)
				}
				timeout = &parsed
			}
			s, err := createStack(configuration, loopback.New(), timeout)
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

func intPtr(n int) *int { return &n }

func TestNewTCPTimeWaitTimeout(t *testing.T) {
	for _, tc := range []struct {
		name    string
		timeout *int
		want    time.Duration
	}{
		{name: "default", want: tcp.DefaultTCPTimeWaitTimeout},
		{name: "zero", timeout: intPtr(0), want: 0},
		{name: "configured", timeout: intPtr(2), want: 2 * time.Second},
	} {
		t.Run(tc.name, func(t *testing.T) {
			n, err := New(&types.Configuration{
				Subnet: "192.168.127.0/24", GatewayIP: "192.168.127.1",
				GatewayMacAddress: "5a:94:ef:e4:0c:dd", MTU: 1500,
				TCPTimeWaitTimeout: tc.timeout,
			})
			if err != nil {
				t.Fatal(err)
			}
			defer n.Close()
			defer n.stack.Close()
			var got tcpip.TCPTimeWaitTimeoutOption
			if err := n.stack.TransportProtocolOption(tcp.ProtocolNumber, &got); err != nil {
				t.Fatal(err)
			}
			if time.Duration(got) != tc.want {
				t.Fatalf("timeout = %v, want %v", time.Duration(got), tc.want)
			}
		})
	}
}

func TestInvalidTCPTimeWaitPreservesCapture(t *testing.T) {
	timeouts := []int{-1}
	if strconv.IntSize == 64 {
		timeouts = append(timeouts, int(int64((1<<63-1)/int64(time.Second))+1))
	}
	for _, timeout := range timeouts {
		t.Run(strconv.Itoa(timeout), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "capture.pcap")
			if err := os.WriteFile(path, []byte("existing"), 0600); err != nil {
				t.Fatal(err)
			}
			_, err := New(&types.Configuration{TCPTimeWaitTimeout: intPtr(timeout), CaptureFile: path})
			if err == nil {
				t.Fatal("expected invalid timeout error")
			}
			data, err := os.ReadFile(path)
			if err != nil || string(data) != "existing" {
				t.Fatalf("capture changed: %q, %v", data, err)
			}
		})
	}
}
