#!/bin/sh -x
sudo ip addr add 192.168.127.0/24 dev O_O
sudo ip link set dev O_O up
sudo route del default gw 192.168.130.1
sudo route add default gw 192.168.127.1 dev O_O
ping -c1 192.168.127.1
