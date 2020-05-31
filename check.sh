#!/bin/sh
set -e
Q=-q

if [ "x$V" = "x1" ]; then
    set -x
    Q=""
fi

# Loopback on Linux: lo, on FreeBSD: lo0
LOOPBACK=`ifconfig |grep LOOPBACK |sed 's/\([lo0-9]*\):.*/\1/'`

./src/ssdpd -n $LOOPBACK &
PID=$!

sleep 1

./src/ssdp-scan |grep $Q 127.0.0.1
kill $PID
