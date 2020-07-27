# gvisor-tap-vsock 

## Host

```
(host) $ sudo bin/host -debug -logtostderr
```

## VM

```
(host) $ scp bin/vm crc:
(host) $ scp setup.sh crc:
(vm) $ sudo ./vm -debug -logtostderr
(vm) $ sudo ./setup.sh
+ sudo ip addr add 192.168.127.0/24 dev O_O
+ sudo ip link set dev O_O up
+ sudo route del default gw 192.168.130.1
+ sudo route add default gw 192.168.127.1 dev O_O
(vm) $ ping -c1 192.168.127.1
(vm) $ curl http://redhat.com
```
