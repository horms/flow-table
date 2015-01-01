#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

static void
flow_table_vlog(const char *fmt, va_list ap)
{
	fprintf(stderr, "flow-table-ctl: ");
	vfprintf(stderr, fmt, ap);
}

void
flow_table_log_err(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	flow_table_vlog(fmt, ap);
	va_end(ap);
}

void
flow_table_log_fatal(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	flow_table_vlog(fmt, ap);
	va_end(ap);

	exit(EXIT_FAILURE);
}
