#!/bin/sh
set -e
Q=-q

if [ "x$V" = "x1" ]; then
    set -x
    Q=""
fi

# Loopback on Linux: lo, on FreeBSD: lo0
which ip >/dev/null
if [ $? -ne 0 ]; then
    # This works with standard ifconfig on Linux and *BSD and
    # non-standard ifconfig from BusyBox
    LOOPBACK=`ifconfig |grep -i LOOPBACK |head -1 | sed 's/\([lo0-9]*\).*/\1/'`
else
    # New Debian/Ubuntu systems don't have ifconfig
    LOOPBACK=`ip link | grep LOOPBACK | sed 's/[0-9]*: \([lo0-9]*\):.*/\1/'`
fi

./src/ssdpd -n $LOOPBACK &
PID=$!

sleep 1

./src/ssdp-scan |grep $Q 127.0.0.1
kill $PID
