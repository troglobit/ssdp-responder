sbin_PROGRAMS  = ssdpd
ssdpd_SOURCES  = ssdpd.c ssdp.h web.c queue.h
ssdpd_CFLAGS   = -W -Wall -Wextra -Wno-unused
ssdpd_CPPFLAGS = -D_GNU_SOURCE
doc_DATA       = README.md LICENSE
EXTRA_DIST     = README.md LICENSE

release: distcheck
	@for file in $(DIST_ARCHIVES); do	\
		md5sum $$file > ../$$file.md5;	\
	done
	@mv $(DIST_ARCHIVES) ../
	@echo
	@echo "Resulting release files in ../"
	@echo "================================================================="
	@for file in $(DIST_ARCHIVES); do					\
		printf "%-32s Distribution tarball\n" $$file;			\
		printf "%-32s " $$file.md5; cat ../$$file.md5 | cut -f1 -d' ';	\
	done
