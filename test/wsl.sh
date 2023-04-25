#!/usr/bin/env bash

set -x

./bin/gvforwarder \
    -url="stdio:$(pwd)/bin/gvproxy-windows.exe?listen-stdio=accept&debug=true" \
    -iface="eth1" \
    -stop-if-exist="" \
    -debug
