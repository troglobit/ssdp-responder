Change Log
==========

All notable changes to the project are documented in this file.


[v1.10][UNRELEASED]
---------------------

### Changes
 - Add support for `-d URL` to override the UPnP description URL, a
   single `%s` is supported to be replaced with the interface address
 - Add support for `-m NAME` to override the `manufacturer` in the
   default `description.xml`
 - Add support for `-M URL` to override the `manufacturerURL` in the
   default `description.xml`
 - Add support for `-p URL` to override the `presentationURL` in the
   default `description.xml`, a single `%s` is supported
 - Add support for `-u UUID` to use a custom UUID, useful when the
   built-in micro HTTP server is disabled
 - Add support for `-w` to disable built-in micro HTTP server, useful
   when other, more capable, web servers are available.  Make sure to
   have the alternate web server running on port 1901 to serve the file
   `/description.xml`, see also `-d URL` above, which details the
   location of the UPnP description URL

### Fixes
 - Fix #11: periodic busy loop causing intermittent 100% CPU load
 - Fix invalid `<UDN>uuid:uuid:...</UDN>` in `description.xml`
 - Add `Date:` and `Server:` to HTTP header in micro HTTP server
 - Add support for HTTP HEAD requests to micro HTTP server
 - Don't overwrite CPPFLAGS from the command line
 - Portability fix to `utimensat()` replacement function


[v1.9][] - 2022-10-30
---------------------

The [Dennis Ritchie](https://www.oreilly.com/content/dennis-ritchie-day/) release.

### Changes
 - Add command line options to `sscp-scan`, mostly for testing but may
   be useful for other purposes too
 - Use `$ac_default_prefix` instead of `/usr/local` in configure script
   when expanding paths
 - Update copyright years (affects LICENSE file hash)
 - Add ChangeLog to project
 - Drop Travis-CI in favor of GitHub Actions

### Fixes
 - Fix #6: workaround for OpenVPN /32 default server setup
 - Fix #9: time-of-check vs time-of-use issue with caching of UUID,
   found by Coverity Scan, fixed by Raul Porancea
 - Fix #10: basic instructions for building and starting the daemon


[v1.8][] - 2021-01-23
---------------------

### Changes
 - Use UUID cache directory from configure script, with fall-back to
   operating system specific `/var/lib/misc` or `/var/db`
 - Update man page with info on UUID cache location
 - Add missing systemd unit file
 - Add missing SysV init script

### Fixes
 - Fix avahi-daemon (mDNS) conflict, no conflict with SSDP, caused by
   copy-paste between mdnsd and project and this
 - Fix default install prefix, should be GNU `/usr/local` not `/`.  The
   default for Debian systems is `/usr`
 - Workaround for `--runstatedir` on systems with older autoconf


[v1.7][] - 2020-06-07
---------------------

### Changes
 - Use `/etc/os-release` as base for SSDP server string, distribution
   release information is primarily stored in this file, some Linux
   systems still use `/etc/lsb-release`, on real UNIX systems we can use
   `uname(1)`
 - Update [ssdpd(8)](https://man.troglobit.com/man8/ssdpd.8.html) man page

### Fixes
 - N/A


[v1.6][] - 2020-06-07
---------------------

### Changes
 - Refactor socket handling, enable `SO_REUSEADDR` + `SO_REUSEPORT`
 - Change default behavior, must now use `-n` to run in foreground
 - Add `ssdp-scan` tool, similar to `mdns-scan`
 - Add systemd unit file
 - Initial Debian/Ubuntu packaging

### Fixes
 - Fix #1: CVE-2019-14323


[v1.5][] - 2017-09-23
---------------------

### Changes
 - New default SSDP notify interval, 300 sec. (Was 600 sec)
 - Validation of refresh and notify intervals, the notify interval must
   not be longer than half the cache timeout
   - Notify: 30-900 sec
   - Refresh: 5-1800 sec

### Fixes
 - Fix regression in v1.3, allow running without interface filtering
 - The new interface filtering feature of v1.4 managed to filter out all
   interfaces if none were given on the command line.
 - Fix CPU overload problem, caused by invalid timer comparison


[v1.4][] - 2017-05-16
---------------------

Minor bug fix release.

### Fixes
 - Fix invalid argument to `accept()` in web server


[v1.3][] - 2017-05-16
---------------------

### Changes
 - Massive refactor
 - Support SSDP per interface and multiple addresses per interface
 - Use `SOCK_DGRAM` instead of `SOCK_RAW`, no longer need to run as root
 - New refresh timer, runs independently of NOTIFY timer, checks for new addresses


[v1.2][] - 2017-05-16
---------------------

Announces itself as an InternetGatewayDevice, works with Windows, serves
XML description.

### Changes
 - Optional `--with-vendor-url=URL` configure option for XML description
 - Read server string from `/etc/lsb-release`, if it exists
 - Save cached version of generated UUID between restarts
 - Make XML manufacturer and modelName configurable


[v1.1][] - 2017-05-12
---------------------

### Changes
 - Generate a proper variant 1, version 4, random session UUID
 - Send notify only for UUID, rootdevice and IGD
 - Weirdly enough the UPnP spec. says the TTL should be 2 for multicast
 - Add UUID to description.xml and remove icon data for now
 - UPnP spec says to use RFC1123 date, as specified in RFC2616
 - Use HTTP/1.1 everywhere, clean up XML a bit
 - `max-age 120` --> 1800 and run web server on SSDP port
 - Add SSDP port to address composition
 - Add `-d` to enable debug mode, with syslog support
 - Add `-v` to list version and update usage text

### Fixes
 - Fix nasty bug in M-SEARCH reply, missing ST rootdevince in USN
 - No need to `sleep(1)` after IGMP join, we can announce w/o it


v1.0 - 2017-05-11
-----------------

Initial release


[UNRELEASED]: https://github.com/troglobit/ssdp-responder/compare/v1.9...HEAD
[v1.9]: https://github.com/troglobit/ssdp-responder/compare/v1.8...v1.9
[v1.8]: https://github.com/troglobit/ssdp-responder/compare/v1.7...v1.8
[v1.7]: https://github.com/troglobit/ssdp-responder/compare/v1.6...v1.7
[v1.6]: https://github.com/troglobit/ssdp-responder/compare/v1.5...v1.6
[v1.5]: https://github.com/troglobit/ssdp-responder/compare/v1.4...v1.5
[v1.4]: https://github.com/troglobit/ssdp-responder/compare/v1.3...v1.4
[v1.3]: https://github.com/troglobit/ssdp-responder/compare/v1.2...v1.3
[v1.2]: https://github.com/troglobit/ssdp-responder/compare/v1.1...v1.2
[v1.1]: https://github.com/troglobit/ssdp-responder/compare/v1.0...v1.1

