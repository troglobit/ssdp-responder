SUBDIRS        = src
man1_MANS      = ssdpd.1
doc_DATA       = README.md LICENSE
EXTRA_DIST     = README.md LICENSE

if HAVE_SYSTEMD
systemd_DATA   = ssdpd.service
endif

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

DISTCHECK_CONFIGURE_FLAGS = --with-systemd=$$dc_install_base/$(systemd)
