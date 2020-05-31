SSDP Responder for Linux/UNIX
=============================
[![License Badge][]][License] [![Travis Status][]][Travis] [![Coverity Status][]][Coverity Scan]

Simple Service Discovery Protocol daemon (SSDP) for networked Linux and
UNIX devices.  Useful in any setup, big or small, but targeted more at
embedded systems that need to announce themselves to Windows systems.

`ssdpd` is a stand-alone UNIX daemon with no external dependencies but
the standard C library.  It has a built-in web server for serving the
UPnP XML description which Windows use to present the icon, by default
an InternetGatewayDevice is announced.

Also included is the `ssdp-scan` tool, which continuously scans for
SSDP capable hosts on the network.  Take care only to use this for
debugging since it scans the network quite aggressively.


Usage
-----

```
Usage: ssdpd [-hnsv] [-i SEC] [-l LEVEL] [-r SEC] [-t TTL] [IFACE [IFACE ...]]

    -h        This help text
    -i SEC    SSDP notify interval (30-900), default 300 sec
    -l LVL    Set log level: none, err, notice (default), info, debug
    -n        Run in foreground, do not daemonize by default
    -r SEC    Interface refresh interval (5-1800), default 600 sec
    -s        Use syslog, default unless running in foreground, -n
    -t TTL    TTL for multicast frames, default 2, according to the UDA
    -v        Show program version

Bug report address : https://github.com/troglobit/ssdp-responder/issues
Project homepage   : https://github.com/troglobit/ssdp-responder
```

See `configure --help` for some build time options.

> **Note:** previous releases did *not* daemonize, you will have to
> update your start scripts to include `-n` as of v1.6


Example
-------

The following example assumes the system `eth0` interface is connected
to an ISP and `eth1` to the LAN.  Every 300 sec the list of addresses
for `eth1` are updated, if a new address is added a `NOTIFY *` message
is sent, otherwise `NOTIFY *` messages are sent every 30 seconds.

```
ssdpd -i 30 -r 300 eth1
```


Origin
------

Cloned from [mrdisc](https://github.com/troglobit/mrdisc) and whacked at
with a bat until it replies to SSDP "MSEARCH *" messages used by Windows.

[License]:         https://en.wikipedia.org/wiki/ISC_license
[License Badge]:   https://img.shields.io/badge/License-ISC-blue.svg
[Travis]:          https://travis-ci.org/troglobit/ssdp-responder
[Travis Status]:   https://travis-ci.org/troglobit/ssdp-responder.png?branch=master
[Coverity Scan]:   https://scan.coverity.com/projects/20496
[Coverity Status]: https://scan.coverity.com/projects/20496/badge.svg
