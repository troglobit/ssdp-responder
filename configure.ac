AC_INIT([ssdpd], [1.6-dev], [https://github.com/troglobit/ssdp-responder/issues],
	[ssdp-responder], [https://github.com/troglobit/ssdp-responder])
AC_CONFIG_AUX_DIR(aux)
AM_INIT_AUTOMAKE([1.11 foreign])

AC_CONFIG_SRCDIR([src/ssdpd.c])
AC_CONFIG_HEADER([config.h])
AC_CONFIG_FILES([Makefile src/Makefile man/Makefile ssdpd.service])

AC_PROG_CC
AC_PROG_INSTALL
PKG_PROG_PKG_CONFIG

# Check if some func is not in libc
AC_CHECK_LIB([util], [pidfile])

# Check for usually missing API's, which we can replace
AC_REPLACE_FUNCS([pidfile strlcpy utimensat])
AC_CONFIG_LIBOBJ_DIR([lib])

# Options
AC_ARG_ENABLE(test-mode,
        AS_HELP_STRING([--enable-test-mode], [Enable loopback test mode]),, [enable_test_mode=no])

AC_ARG_WITH([vendor],
	AS_HELP_STRING([--with-vendor=VENDOR], [Set a custom vendor string]),
	[vendor=$withval], [vendor="Troglobit Software Systems"])

AC_ARG_WITH([vendor-url],
	AS_HELP_STRING([--with-vendor-url=VENDOR], [Set vendor URL]))

AC_ARG_WITH([model],
	AS_HELP_STRING([--with-model=MODEL], [Set a custom model string]),
	[model=$withval], [model="Generic"])

AC_ARG_WITH([systemd],
     [AS_HELP_STRING([--with-systemd=DIR], [Directory for systemd service files])],,
     [with_systemd=auto])

AS_IF([test "x$enable_test_mode" == "xyes"], [
	AC_DEFINE(TEST_MODE, 1, [Loopback test mode])])
AM_CONDITIONAL([TEST_MODE], [test "x$enable_test_mode" == "xyes"])

AS_IF([test "x$with_vendor_url" != "xno" -a "x$with_vendor_url" != "xyes"], [
	AC_DEFINE_UNQUOTED(MANUFACTURER_URL, "$with_vendor_url", [Manufacturer URL in XML])])

AS_IF([test "x$with_vendor" != "xno"], [
	AS_IF([test "x$vendor" = "xyes"], [
		vendor="Troglobit Software Systems"])])
AC_DEFINE_UNQUOTED(MANUFACTURER, "$vendor", [Manufacturer in XML])

AS_IF([test "x$with_model" != "xno"], [
	AS_IF([test "x$model" = "xyes"], [
		model="Generic"])])
AC_DEFINE_UNQUOTED(MODEL, "$model", [Model name in XML])

# Check where to install the systemd .service file
AS_IF([test "x$with_systemd" = "xyes" -o "x$with_systemd" = "xauto"], [
     def_systemd=$($PKG_CONFIG --variable=systemdsystemunitdir systemd)
     AS_IF([test "x$def_systemd" = "x"],
         [AS_IF([test "x$with_systemd" = "xyes"],
            [AC_MSG_ERROR([systemd support requested but pkg-config unable to query systemd package])])
            with_systemd=no], [with_systemd="$def_systemd"])]
)
AS_IF([test "x$with_systemd" != "xno"],
     [AC_SUBST([systemddir], [$with_systemd])])
AM_CONDITIONAL([HAVE_SYSTEMD], [test "x$with_systemd" != "xno"])

# Expand variables early, for systemd unit file and others
test "x$prefix" = "xNONE" && prefix=
test "x$exec_prefix" = "xNONE" && exec_prefix='${prefix}'

SBINDIR=`eval echo $sbindir`
SBINDIR=`eval echo $SBINDIR`
AC_SUBST(SBINDIR)

# Create all config files
AC_OUTPUT
