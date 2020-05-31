#!/bin/sh
IFCONF=`which ifconfig`
LEVEL=warning
PID=""
Q=-q

echo setup

trap 'exit 1' INT HUP QUIT TERM ALRM USR1
trap 'cleanup' EXIT

cleanup()
{
    echo cleanup
    [ -n "$PID" ] && kill $PID
}

set -e
if [ "x$V" = "x1" ]; then
    set -x
    LEVEL=debug
    Q=""
fi

# Loopback on Linux: lo, on FreeBSD: lo0
if [ -n "$IFCONF" ]; then
    # This works with standard ifconfig on Linux and *BSD and
    # non-standard ifconfig from BusyBox
    LOOPBACK=`$IFCONF |grep -i LOOPBACK |head -1 | sed 's/\([lo0-9]*\).*/\1/'`
else
    # New Debian/Ubuntu systems don't have ifconfig
    LOOPBACK=`ip link | grep LOOPBACK | sed 's/[0-9]*: \([lo0-9]*\):.*/\1/'`
fi

echo test

./src/ssdpd -l $LEVEL -n $LOOPBACK &
PID=$!

sleep 1

[ -z "$Q" ] && curl http://127.0.0.1:8080/description.xml

./src/ssdp-scan $LOOPBACK |grep $Q 127.0.0.1
kill $PID

echo ok
exit 0
