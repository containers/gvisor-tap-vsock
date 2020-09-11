# gvisor-tap-vsock 

A replacement for [VPNKit](https://github.com/moby/vpnkit), written in pure Go.

## How it works

### Internet access

![schema](./doc/curl.png)

0. A tap network interface is running in the VM. It's the default gateway.
1. User types `curl redhat.com`
2. Linux kernel sends raw Ethernet packets to the tap device.
3. Tap device sends these packets to a process on the host using [vsock](https://wiki.qemu.org/Features/VirtioVsock)
4. The process on the host maintains both internal (host to VM) and external (host to Internet endpoint) connections. It uses regular syscalls to connect to external endpoints. 

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

For CRC, the driver should be compiled with this patch: https://github.com/code-ready/machine-driver-libvirt/pull/45.

#### macOS prerequisites

Please locate the hyperkit state (there is a file called `connect` inside) folder and launch `host` with the following env variable:
`VM_DIRECTORY=path_to_connect_directory`

For CRC, the driver should be compiled with this patch: https://github.com/code-ready/machine-driver-hyperkit/pull/12.

#### Run

```
(host) $ sudo bin/host -debug
```

### VM

```
(vm) # docker run -d --name=gvisor-tap-vsock --privileged --net=host -it quay.io/crcont/gvisor-tap-vsock:latest
(vm) $ ping -c1 192.168.127.1
(vm) $ curl http://redhat.com
```

### Internal DNS

Activate it by changing the `/etc/resolv.conf` file inside the VM with:
```
nameserver 192.168.127.1
```


## Performance

Using iperf3, running the server on the host and the client in the VM, it can achieve 600Mbits/s.
