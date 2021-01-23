AUTOMAKE_OPTIONS = subdir-objects
AM_CFLAGS        = -W -Wall -Wextra -Wno-unused -std=c11
AM_CPPFLAGS      = -D_PIDFILEDIR=\"@runstatedir@\" -D_CACHEDIR=\"@localstatedir@/@vardb@\"
AM_CPPFLAGS     += -D_FORTIFY_SOURCE=2

bin_PROGRAMS     = ssdp-scan
sbin_PROGRAMS    = ssdpd

ssdpd_SOURCES    = ssdpd.c compat.h ssdp.c ssdp.h web.c queue.h
ssdpd_LDADD      = $(LIBS) $(LIBOBJS)

ssdp_scan_SOURCES = ssdp-scan.c compat.h ssdp.c ssdp.h uget.c queue.h
ssdp_scan_LDADD   = $(LIBS) $(LIBOBJS)
