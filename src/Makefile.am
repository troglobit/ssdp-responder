AUTOMAKE_OPTIONS = subdir-objects
AM_CFLAGS        = -W -Wall -Wextra -Wno-unused
AM_CPPFLAGS      = -D_GNU_SOURCE -DLOCALSTATEDIR=\"@localstatedir@\"

bin_PROGRAMS     = ssdp-scan
sbin_PROGRAMS    = ssdpd
ssdpd_SOURCES    = ssdpd.c ssdp.h web.c queue.h
ssdpd_LDADD      = $(LIBS) $(LIBOBJS)

ssdp_scan_SOURCES = ssdp-scan.c ssdp.h uget.c queue.h
ssdp_scan_LDADD   = $(LIBS) $(LIBOBJS)
