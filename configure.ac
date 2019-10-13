AC_INIT([ssdpd], [1.6-dev], [https://github.com/troglobit/ssdp-responder/issues],
	[ssdp-responder], [https://github.com/troglobit/ssdp-responder])
AM_INIT_AUTOMAKE([1.11 foreign])

AC_CONFIG_SRCDIR([src/ssdpd.c])
AC_CONFIG_HEADER([config.h])
AC_CONFIG_FILES([Makefile src/Makefile])

AC_PROG_CC
AC_PROG_INSTALL
AC_HEADER_STDC

# Check if some func is not in libc
AC_CHECK_LIB([util], [pidfile])

# Check for usually missing API's, which we can replace
AC_REPLACE_FUNCS([pidfile utimensat])
AC_CONFIG_LIBOBJ_DIR([lib])

# Options
AC_ARG_WITH([vendor],
	AS_HELP_STRING([--with-vendor=VENDOR], [Set a custom vendor string]),
	[vendor=$withval], [vendor="Troglobit Software Systems"])
AC_ARG_WITH([vendor-url],
	AS_HELP_STRING([--with-vendor-url=VENDOR], [Set vendor URL]))
AC_ARG_WITH([model],
	AS_HELP_STRING([--with-model=MODEL], [Set a custom model string]),
	[model=$withval], [model="Generic"])

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

# Create all config files
AC_OUTPUT
