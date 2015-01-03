lib_LTLIBRARIES += lib/libflow-table.la

lib_libflow_table_la_LDFLAGS = \
        -version-info $(LT_CURRENT):$(LT_REVISION):$(LT_AGE) \
        -Wl,--version-script=$(top_builddir)/lib/libflow-table.sym \
        $(AM_LDFLAGS)


lib_libflow_table_la_SOURCES = \
	lib/data.c \
	lib/json.c \
	lib/msg.c \
	lib/nla-policy.c \
	lib/nla-policy.h

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA += lib/libflow-table.pc
