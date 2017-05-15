[![License Badge][]][License] [![Travis Status][]][Travis]

Prototype micro SSDP responder for networked devices.

Usage
-----

```
Usage: ssdpd [-dhv] [-i SEC] IFACE [IFACE ...]

    -d        Developer debug mode
    -h        This help text
    -i SEC    Announce interval, default 30 sec
    -v        Show program version

Bug report address: https://github.com/troglobit/ssdp-responder/issues
```

Origin
------

Cloned from [mrdisc](https://github.com/troglobit/mrdisc) and whacked at
with a bat until it replies to SSDP "MSEARCH *" messages used by Windows.

[License]:       https://en.wikipedia.org/wiki/ISC_license
[License Badge]: https://img.shields.io/badge/License-ISC-blue.svg
[Travis]:        https://travis-ci.org/troglobit/ssdp-responder
[Travis Status]: https://travis-ci.org/troglobit/ssdp-responder.png?branch=master
