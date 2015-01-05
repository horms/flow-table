/* Based on:
 *
 * include/linux/net/if_flow.h - Flow table interface for Switch devices
 * Copyright (c) 2014 John Fastabend <john.r.fastabend@intel.com>
 *
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * The full GNU General Public License is included in this distribution in
 * the file called "COPYING".
 *
 * Author: John Fastabend <john.r.fastabend@intel.com>
 */

#ifndef _FLOW_TABLE_TYPES_H
#define _FLOW_TABLE_TYPES_H

#include <linux/if_flow.h>

/**
 * @struct net_flow_action
 * @brief a description of a endpoint defined action
 *
 * @name printable name
 * @uid unique action identifier
 * @types NET_FLOW_ACTION_TYPE_NULL terminated list of action types
 */
struct net_flow_action {
	char name[NET_FLOW_NAMSIZ];
	int uid;
	struct net_flow_action_arg *args;
};

/**
 * @struct net_flow_flow
 * @brief describes the match/action entry
 *
 * @uid unique identifier for flow
 * @priority priority to execute flow match/action in table
 * @match null terminated set of match uids match criteria
 * @actoin null terminated set of action uids to apply to match
 *
 * Flows must match all entries in match set.
 */
struct net_flow_flow {
	int table_id;
	int uid;
	int priority;
	struct net_flow_field_ref *matches;
	struct net_flow_action *actions;
};

#endif
