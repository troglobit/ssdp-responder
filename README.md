SSDP Responder for Linux/UNIX
=============================
[![License Badge][]][License] [![GitHub Status][]][GitHub] [![Coverity Status][]][Coverity Scan]

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
Usage: ssdpd [-hnsvw] [-d URL] [-i SEC] [-l LEVEL] [-m NAME] [-M URL] [-p URL]
                      [-r SEC] [-t TTL] [-u UUID] [IFACE [IFACE ...]]

    -d URL    Override UPnP description.xml URL in announcements.  The '%s' in
              the URL is replaced with the IP, e.g. https://%s:1901/main.xml
    -h        This help text
    -i SEC    SSDP notify interval (30-900), default 300 sec
    -l LVL    Set log level: none, err, notice (default), info, debug
    -m NAME   Override manufacturer in the default description.xml
    -M URL    Override manufacturerURL in the default description.xml
    -n        Run in foreground, do not daemonize by default
    -r SEC    Interface refresh interval (5-1800), default 600 sec
    -p URL    Override presentationURL (WebUI) in the default description.xml
              The '%s' is replaced with the IP address.  Default: http://%s/
    -s        Use syslog, default unless running in foreground, -n
    -t TTL    TTL for multicast frames, default 2, according to the UDA
    -u UUID   Custom UUID instead of auto-generating one
    -v        Show program version
    -w        Disable built-in micro HTTP server on port 1901

Bug report address : https://github.com/troglobit/ssdp-responder/issues
Project homepage   : https://github.com/troglobit/ssdp-responder
```

The `-d URL` argument can contain one `%s` modifier which is replaced
with the IP address of the interface the SSDP notification or reply is
sent on.  For example:

    ssdpd -d https://%s:1901/description.xml

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


Configure & Build
-----------------

The GNU Configure & Build system use `/usr/local` as the default install
prefix.  In many cases this is useful, but this means the configuration
files, cache, and PID files will also use that prefix.  Most users have
come to expect those files in `/etc/` and `/var/` and configure has a
few useful options that are recommended to use.  Hence, you may want to
use something like this:

    ./configure --prefix=/usr --sysconfdir=/etc --runstatedir=/var/run
    make -j$(($(nproc) + 1))
    sudo make install-strip

Usually your system reserves `/usr` for native pacakges, so most users
drop `--prefix`, installing to `/usr/local`, or use `--prefix=/opt`.

**Note:** On some systems `--runstatedir` may not be available in the
  configure script, try `--localstatedir=/var` instead.


### Building from GIT

The `configure` script and the `Makefile.in` files are generated for
release tarballs and not stored in GIT.  When you work with the GIT
source tree you need the GNU `automake` and `autoconf` tools:

    $ sudo apt install automake autoconf

Now, from the top directory of the cloned GIT tree, call:

    $ ./autogen.sh


### Static Build

Some people want to build statically, to do this with `autoconf` add the
following `LDFLAGS=` *after* the configure script.  You may also need to
add `LIBS=...`, which will depend on your particular system:

    ./configure LDFLAGS="-static" ...


Integration with systemd
------------------------

For systemd integration `libsystemd-dev` and `pkg-config` are required.
When the unit file is installed, `systemctl` can be used to enable and
start the daemon:

    $ sudo systemctl enable ssdpd.service
    $ sudo systemctl start  ssdpd.service

Check that it started properly by inspecting the system log, or:

    $ sudo systemctl status ssdpd.service

To stop the service:

    $ sudo systemctl stop   ssdpd.service


Origin
------

Cloned from [mrdisc](https://github.com/troglobit/mrdisc) and whacked at
with a bat until it replies to SSDP "MSEARCH *" messages used by Windows.

[License]:         https://en.wikipedia.org/wiki/ISC_license
[License Badge]:   https://img.shields.io/badge/License-ISC-blue.svg
[GitHub]:          https://github.com/troglobit/ssdp-responder/actions/workflows/build.yml/
[GitHub Status]:   https://github.com/troglobit/ssdp-responder/actions/workflows/build.yml/badge.svg
[Coverity Scan]:   https://scan.coverity.com/projects/20496
[Coverity Status]: https://scan.coverity.com/projects/20496/badge.svg
