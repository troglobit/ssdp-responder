SUBDIRS        = src man
doc_DATA       = README.md LICENSE
EXTRA_DIST     = README.md LICENSE

if HAVE_SYSTEMD
systemd_DATA   = ssdpd.service
endif

if TEST_MODE
check: all
	@echo "Loopback test ..."
	@./src/ssdpd lo
	@./src/ssdp-scan |grep -q 127.0.0.1
	@killall ssdpd
	@echo "Loopback test OK!"
else
check:
	@echo "Test mode disabled."
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
