#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT(flow-table, 0.1, simon.horman@netronome.com)
AC_CONFIG_SRCDIR([flow-table-ctl/flow-table-ctl.c])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE

# Checks for programs.
AC_PROG_CC_C99
AC_PROG_CC
AC_PROG_INSTALL

AM_MISSING_PROG([AUTOM4TE], [autom4te])

LT_INIT()
m4_pattern_forbid([LT_INIT]) dnl Make autoconf fail if libtool is missing.
m4_define([libflow_table_lt_current],    [0])
m4_define([libflow_table_lt_revision],   [0])
m4_define([libflow_table_lt_age],        [0])

LT_CURRENT=libflow_table_lt_current
AC_SUBST([LT_CURRENT])
LT_REVISION=libflow_table_lt_revision
AC_SUBST([LT_REVISION])
LT_AGE=libflow_table_lt_age
AC_SUBST([LT_AGE])

# Checks for libraries.
PKG_CHECK_MODULES(LIBNL_GENL_3, libnl-genl-3.0 >= 3.1,
                  [have_libnl_genl_3=yes], [have_libnl_genl_3=no])
if (test "${have_libnl_genl_3}" = "yes"); then
	CFLAGS+=" $LIBNL_GENL_3_CFLAGS"
	LIBS+=" $LIBNL_GENL_3_LIBS"
fi

PKG_CHECK_MODULES(LIBNL_ROUTE_3, libnl-route-3.0 >= 3.1,
                  [have_libnl_route_3=yes], [have_libnl_route_3=no])
if (test "${have_libnl_route_3}" = "yes"); then
	CFLAGS+=" $LIBNL_ROUTE_3_CFLAGS"
	LIBS+=" $LIBNL_ROUTE_3_LIBS"
fi

PKG_CHECK_MODULES(JSON_C, json-c, [have_json_c=yes], [have_json_c=no])
if (test "${have_json_c}" = "yes"); then
	CFLAGS+=" $JSON_C_CFLAGS"
	LIBS+=" $JSON_C_LIBS"
fi

# Checks for header files.
AC_CHECK_HEADERS([stdlib.h])

# Checks for typedefs, structures, and compiler characteristics.

# Checks for library functions.

AC_CONFIG_FILES(Makefile)
AC_CONFIG_FILES(lib/libflow-table.pc)
AC_CONFIG_FILES(lib/libflow-table.sym)

AC_OUTPUT
