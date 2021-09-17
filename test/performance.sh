#!/usr/bin/env bash

set -x

VM=$1
GVPROXY_SOCKET=$2

echo "Testing Internet access with a server running on the host"

nohup iperf3 -s > /dev/null 2>&1 &
serverPID=$!

ssh $VM curl https://iperf.fr/download/ubuntu/libiperf.so.0_3.1.3 -o libiperf.so.0
ssh $VM curl https://iperf.fr/download/ubuntu/iperf3_3.1.3 -o iperf3
ssh $VM chmod +x iperf3

echo "TCP: sending data"
ssh $VM LD_LIBRARY_PATH=. ./iperf3 -c host.crc.testing
echo "TCP: receiving data"
ssh $VM LD_LIBRARY_PATH=. ./iperf3 -c host.crc.testing -R

echo "UDP: sending data"
ssh $VM LD_LIBRARY_PATH=. ./iperf3 -c host.crc.testing -u
echo "UDP: receiving data"
ssh $VM LD_LIBRARY_PATH=. ./iperf3 -c host.crc.testing -R -u

kill $serverPID

echo "Testing forwarder with a server running in the VM"

curl --unix-socket $GVPROXY_SOCKET http:/unix/services/forwarder/expose -X POST \
  -d'{"local":":5201", "protocol": "udp", "remote": "192.168.127.2:5201"}'
curl --unix-socket $GVPROXY_SOCKET http:/unix/services/forwarder/expose -X POST \
  -d'{"local":":5201", "protocol": "tcp", "remote": "192.168.127.2:5201"}'

ssh $VM LD_LIBRARY_PATH=. ./iperf3 -s > /dev/null 2>&1 &
sleep 1

echo "TCP: sending data"
iperf3 -c 127.0.0.1
echo "TCP: receiving data"
iperf3 -c 127.0.0.1 -R

echo "UDP: sending data"
iperf3 -c 127.0.0.1 -u -l 9216
echo "UDP: receiving data"
iperf3 -c 127.0.0.1 -R -u -l 9216

ssh $VM pkill iperf3

curl --unix-socket $GVPROXY_SOCKET http:/unix/services/forwarder/unexpose -X POST \
  -d'{"local":":5201", "protocol": "udp"}'
curl --unix-socket $GVPROXY_SOCKET http:/unix/services/forwarder/unexpose -X POST \
  -d'{"local":":5201", "protocol": "tcp"}'
