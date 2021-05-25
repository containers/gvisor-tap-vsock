# gvisor-tap-vsock 

A replacement for [VPNKit](https://github.com/moby/vpnkit), written in pure Go.
It is based on the network stack of [gVisor](https://github.com/google/gvisor/tree/master/pkg/tcpip).

## How it works

### Internet access

![schema](./doc/curl.png)

0. A tap network interface is running in the VM. It's the default gateway.
1. User types `curl redhat.com`
2. Linux kernel sends raw Ethernet packets to the tap device.
3. Tap device sends these packets to a process on the host using [vsock](https://wiki.qemu.org/Features/VirtioVsock)
4. The process on the host maintains both internal (host to VM) and external (host to Internet endpoint) connections. It uses regular syscalls to connect to external endpoints. 

This is the same behaviour as [slirp](https://wiki.qemu.org/index.php/Documentation/Networking#User_Networking_.28SLIRP.29). 

### Expose a port

![schema](./doc/http.png)

1. The process on the host binds the port 80. 
2. Each time, a client sends a http request, the process creates and sends the appropriate Ethernet packets to the VM.
3. The tap device receives the packets and injects them in the kernel.
4. The http server receives the request and send back the response.

## Build

```
make
```

## Run

### Host

#### Windows prerequisites

```
$service = New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Virtualization\GuestCommunicationServices" -Name "00000400-FACB-11E6-BD58-64006A7986D3"
$service.SetValue("ElementName", "gvisor-tap-vsock")
```

More docs: https://docs.microsoft.com/en-us/virtualization/hyper-v-on-windows/user-guide/make-integration-service

In the VM, be sure to have `hv_sock` module loaded.

#### Linux prerequisites

On Fedora 32, it worked out of the box. On others distros, you might have to look at https://github.com/mdlayher/vsock#requirements.

#### macOS prerequisites

Please locate the hyperkit state (there is a file called `connect` inside) folder and launch `gvproxy` with the following listen argument:
`--listen vsock://null:1024/path_to_connect_directory`

#### Run

```
(host) $ sudo bin/gvproxy -debug -listen vsock://:1024 -listen unix:///tmp/network.sock
```

### VM

With a container:
```
(vm) # docker run -d --name=gvisor-tap-vsock --privileged --net=host -it quay.io/crcont/gvisor-tap-vsock:latest
(vm) $ ping -c1 192.168.127.1
(vm) $ curl http://redhat.com
```

With the executable:
```
(vm) # ./vm -debug
```

### Services

#### API

The executable running on the host, `gvproxy`, exposes a HTTP API. It can be used with curl.

```
$ curl  --unix-socket /tmp/network.sock http:/unix/stats 
{
  "BytesSent": 0,
  "BytesReceived": 0,
  "UnknownProtocolRcvdPackets": 0,
  "MalformedRcvdPackets": 0,
...
```

#### Gateway

The executable running on the host runs a virtual gatewat that can be used by the VM.

#### DNS

The gateway also runs a DNS server. It can be configured to serve static zones.

Activate it by changing the `/etc/resolv.conf` file inside the VM with:
```
nameserver 192.168.127.1
```

#### Port forwarding

Dynamic port forwarding is supported.

Expose a port:
```
$ curl  --unix-socket /tmp/network.sock http:/unix/services/forwarder/expose -X POST -d '{"local":":6443","remote":"192.168.127.2:6443"}'
```

Unexpose a port:
```
$ curl  --unix-socket /tmp/network.sock http:/unix/services/forwarder/expose -X POST -d '{"local":":6443"}'
```

List exposed ports:
```
$ curl  --unix-socket /tmp/network.sock http:/foo/services/forwarder/all | jq .
[
  {
    "local": ":2222",
    "remote": "192.168.127.2:22"
  },
  {
    "local": ":6443",
    "remote": "192.168.127.2:6443"
  }
]

```

#### Tunneling 

The HTTP API exposed on the host can be used to connect to a specific IP and port inside the virtual network.
An working example for SSH can be found [here](https://github.com/containers/gvisor-tap-vsock/blob/master/cmd/ssh-over-vsock).

## Limitations

* ICMP is not forwarded outside the network.

## Performance

Using iperf3, running the server on the host and the client in the VM, it can achieve 600Mbits/s.
