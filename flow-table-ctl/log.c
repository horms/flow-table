/*
 * libflowtable: A user-space library for a Linux Kernel Flow API
 *
 * Copyright (C) 2015  Netronome.
 *
 * Contacts: Simon Horman <simon.horman@netronome.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; version 2 of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

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
