bin_PROGRAMS += flow-table-ctl/flow-table-ctl

flow_table_ctl_flow_table_ctl_CPPFLAGS =  $(AM_CPPFLAGS)
flow_table_ctl_flow_table_ctl_LDADD = lib/libflow-table.la
flow_table_ctl_flow_table_ctl_SOURCES = \
	flow-table-ctl/flow-table-ctl.c \
	flow-table-ctl/log.c \
	flow-table-ctl/log.h \
	flow-table-ctl/unused.h
