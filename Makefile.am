SUBDIRS        = src man
doc_DATA       = README.md LICENSE
EXTRA_DIST     = README.md LICENSE

if HAVE_SYSTEMD
systemd_DATA   = ssdpd.service
endif

if TEST_MODE
check: all
	@./check.sh
else
check:
	@echo "Test mode disabled."
endif

## Generate .deb package
package:
	@debuild -uc -us -B --lintian-opts --profile debian -i -I --show-overrides

## Check if tagged in git
release-hook:
	if [ "x`git tag -l v$(PACKAGE_VERSION)|grep v$(PACKAGE_VERSION)`" = "x" ]; then	\
		echo;									\
		printf "\e[1m\e[41mCannot find release tag v$(PACKAGE_VERSION)\e[0m\n";	\
		printf "\e[1m\e[5mDo release anyway?\e[0m "; read yorn;			\
		if [ "$$yorn" != "y" -a "$$yorn" != "Y" ]; then				\
			printf "OK, aborting release.\n";				\
			exit 1;								\
		fi;									\
		echo;									\
	else										\
		echo;									\
		printf "\e[1m\e[42mFound GIT release tag v$(PACKAGE_VERSION)\e[0m\n";	\
		printf "\e[1m\e[44m>>Remember to push tags!\e[0m\n";			\
		echo;									\
	fi

release: release-hook distcheck package
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
	@for file in `cd ..; ls ssdpd_$(VERSION)* ssdp-scan_$(VERSION)*`; do	\
		printf "%-32s Debian/Ubuntu package\n" $$file;			\
	done

DISTCHECK_CONFIGURE_FLAGS = --with-systemd=$$dc_install_base/$(systemd)
