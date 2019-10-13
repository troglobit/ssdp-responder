AUTOMAKE_OPTIONS = subdir-objects
AM_CPPFLAGS      = -D_GNU_SOURCE -DLOCALSTATEDIR=\"@localstatedir@\"

sbin_PROGRAMS    = ssdpd
ssdpd_SOURCES    = ssdpd.c ssdp.h web.c queue.h
ssdpd_CFLAGS     = -W -Wall -Wextra -Wno-unused
ssdpd_LDADD      = $(LIBS) $(LIBOBJS)
