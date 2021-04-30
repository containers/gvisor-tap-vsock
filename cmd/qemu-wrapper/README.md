Qemu doesn't accept a unix socket as netdev, only a file descriptro.
This wrapper is filling the gap.

```
$ ./qemu-wrapper /tmp/qemu.sock qemu-system-x86_64 [...] -netdev socket,id=vlan,fd=3 -device virtio-net-pci,netdev=vlan
```
