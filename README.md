# gvisor-tap-vsock 

A replacement for [VPNKit](https://github.com/moby/vpnkit), written in pure Go.

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
(host) $ sudo bin/host -debug -logtostderr
```

### VM

```
(host) $ scp bin/vm crc:
(host) $ scp setup.sh crc:
(vm terminal 1) $ sudo ./vm -debug -logtostderr [-windows if using windows]
(vm terminal 2) $ sudo ./setup.sh
+ sudo ip addr add 192.168.127.0/24 dev O_O
+ sudo ip link set dev O_O up
+ sudo route del default gw 192.168.130.1
+ sudo route add default gw 192.168.127.1 dev O_O
(vm terminal 2) $ ping -c1 192.168.127.1
(vm terminal 2) $ curl http://redhat.com
```

### Internal DNS

Activate it by changing the `/etc/resolv.conf` file inside the VM with:
```
nameserver 192.168.127.1
```


## Performance

Using iperf3, running the server on the host and the client in the VM, it can achieve 600Mbits/s.


## Inverted

make selinux
podman run -d --privileged --net=host -it quay.io/gurose/gvisor-tap-vsock

