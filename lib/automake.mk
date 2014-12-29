lib_LTLIBRARIES += lib/libflow-table.la

lib_libflow_table_la_LDFLAGS = \
        -version-info $(LT_CURRENT):$(LT_REVISION):$(LT_AGE) \
        -Wl,--version-script=$(top_builddir)/lib/libflow-table.sym \
        $(AM_LDFLAGS)


lib_libflow_table_la_SOURCES = \
	lib/msg.c

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA += lib/libflow-table.pc
