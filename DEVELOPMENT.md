### Running tests

#### Functional tests

Run the functional test suite for your platform:
```shell
# macOS (vfkit)
make test-mac

# QEMU (Linux or macOS)
make test-qemu
```

#### Performance tests

Performance tests measure network throughput, latency, and API overhead of the
gvisor-tap-vsock stack. They spin up a full VM (Fedora CoreOS), deploy the
`test-companion` binary inside it, and run benchmarks between host and guest.

##### Prerequisites

- `iperf3` installed on the host (`brew install iperf3` / `dnf install iperf3`)
- A working hypervisor: vfkit on macOS, QEMU on Linux (or macOS with `qemu-system-*`)
- The project binaries built: `make gvproxy test-companion`

##### Running

```shell
# macOS (vfkit backend, ~30 min)
make test-perf-mac

# QEMU backend (~30 min)
make test-perf-qemu
```

You can also run individual test suites with `go test` flags:
```shell
# Run only throughput tests
go test -timeout 30m -v ./test-performance-vfkit -run "iperf3 throughput"

# Run only latency tests
go test -timeout 30m -v ./test-performance-qemu -run "latency"
```

##### What is measured

| Test suite                | Metrics reported                       | Unit      |
|---------------------------|----------------------------------------|-----------|
| iperf3 throughput         | TCP/UDP send and receive (both directions) | Mbps      |
| iperf3 via port forwarding| TCP/UDP through gvproxy port forwarding| Mbps      |
| iperf3 parallel streams   | TCP with 1, 4, 8 concurrent streams   | Mbps      |
| iperf3 UDP payload sizes  | UDP with 128, 512, 1460, 9216 byte payloads | Mbps  |
| latency                   | ICMP ping to gateway and external host (min/avg/max/mdev) | ms |
| DNS resolution            | Internal and external DNS lookup time (avg/P95/max) | ms |
| port forwarding ops       | Expose/Unexpose API latency (avg/P95)  | us        |
| HTTP request rate         | Requests per second and average latency through port forwarding | req/s, ms |

##### Interpreting results

After all tests complete, a summary table is printed:
```
========================================================================
  PERFORMANCE TEST RESULTS
========================================================================

  iperf3 throughput > should measure TCP throughput from VM to host   [PASS]
  ---------------------------------------------------------------
    tcp_vm_to_host_sent        2145.32 Mbps
    tcp_vm_to_host_received    2131.87 Mbps

  latency > should measure ICMP latency to gateway                   [PASS]
  ------------------------------------------------
    ping_gateway_min_ms        0.234
    ping_gateway_avg_ms        0.512
    ping_gateway_max_ms        1.103
    ping_gateway_mdev_ms       0.187

========================================================================
  Total: 18 passed, 0 failed, 0 skipped
========================================================================
```

Key things to look for:

- **Throughput** (iperf3 tests): higher is better. Direct VM-to-host TCP should
  typically reach 1.5-3+ Gbps depending on your hardware. Port-forwarded
  throughput will be lower due to the extra hop through gvproxy.
- **Latency** (ping/DNS tests): lower is better. Gateway ping avg should be
  sub-millisecond. External ping includes real network latency beyond the stack.
- **UDP loss percentage**: should be 0% or near-0% for internal traffic. Non-zero
  loss may indicate buffer pressure or packet drops in the network stack.
- **Port forwarding ops**: expose/unexpose are API calls to gvproxy. Average
  latency in the low hundreds of microseconds is typical.
- **HTTP request rate**: measures end-to-end overhead of port forwarding for
  small HTTP requests. Higher req/s means lower per-request overhead.

Compare results across runs on the same hardware to detect performance
regressions. Absolute numbers vary significantly by machine, hypervisor, and
host load.

### Debugging test

#### MacOS

You could debug tests with [Delve](https://github.com/go-delve/delve) debugger.
Run:
```shell
make test-mac-debug
```
This command will run build `gvisor` binary with debugger enabled.

>Note: By default it would use `--continue` `dlv` option to not pause `gvisor` execution on start, if debugger is not connected.
> To pause `gvisor` execution until debugger is connected just remove `"--continue"` parameter from this [line](./test-vfkit/vfkit_suite_test.go#L93) 

And debug server with `2345` port, you could use any `delve` client to interact with debugger

##### GoLand Example
Create new `Go Remote` debug configuration:
1. Click Edit | Run Configurations. Alternatively, click the list of run/debug configurations on the toolbar and select Edit Configurations.
2. In the Run/Debug Configurations dialog, click the Add button (the Add button) and select Go Remote.
3. Set meaningful name
4. In the Host field, keep `localhost`
5. In the Port field, keep `2345` port number
6. Click **OK** button

Run `gvisor` tests with debug with:
```shell
make test-mac-debug
```
wait until `Listening for remote connections (connections are not authenticated nor encrypted)` message it appears.
Click on debug button on Golang, ensure that your `Go Remote` profile is selected.

Have fun with debugging.

##### VSCode
Create/edit `launch.json` by adding this configuration:
```json
   {
      "name": "Connect to Gvisor",
      "type": "go",
      "request": "attach",
      "mode": "remote",
      "remotePath": "${workspaceFolder}",
      "port": 2345,
      "host": "localhost"
    }
```
Run `gvisor` tests with debug with:
```shell
make test-mac-debug
```
wait until `Listening for remote connections (connections are not authenticated nor encrypted)` message it appears.
Execute the launch attach request(`Connect to Gvisor`).

Have fun with debugging.

##### CLI Example

Connect to debugger server with:
```shell
dlv connect :2345
```
Example of usage:
```shell
Type 'help' for list of commands.
(dlv) break main.main
Breakpoint 1 set at 0xe735776 for main.main() ./work/redhat/gvisor-tap-vsock/cmd/gvproxy/main.go:59
(dlv) continue
> [Breakpoint 1] main.main() ./work/redhat/gvisor-tap-vsock/cmd/gvproxy/main.go:59 (hits goroutine(1):1 total:1) (PC: 0xe735776)
    54:         hostIP      = "192.168.127.254"
    55:         host        = "host"
    56:         gateway     = "gateway"
    57: )
    58:
=>  59: func main() {
    60:         version := types.NewVersion("gvproxy")
    61:         version.AddFlag()
    62:         flag.Var(&endpoints, "listen", "control endpoint")
    63:         flag.BoolVar(&debug, "debug", false, "Print debug info")
    64:         flag.IntVar(&mtu, "mtu", 1500, "Set the MTU")
```
More info about CLI client [here](https://github.com/go-delve/delve/blob/master/Documentation/cli/README.md)

#### Editor integration

For available editor integration look [there](https://github.com/go-delve/delve/blob/master/Documentation/EditorIntegration.md)