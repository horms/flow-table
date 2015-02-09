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

#ifndef FLOW_TABLE_MSG_H
#define FLOW_TABLE_MSG_H

#include <netlink/netlink.h>

#include <flow-table/types.h>

struct nl_msg *
flow_table_msg_put(int family, int ifindex, int cmd);

struct nl_msg *
flow_table_msg_put_get_flows_request(int family, int ifindex, int table,
				     int min_prio, int max_prio);

int
flow_table_get_ifindex(struct nlattr **attrs);

int
flow_table_get_ifindex_from_request(struct nlattr *attr);

int
flow_table_flows_request(struct nlattr *attr,
			 int (*cb)(const struct net_flow_rule *flow,
				   void *data),
			 void *cb_data);
#endif
