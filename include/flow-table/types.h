/*
 * libflowtable: A user-space library for a Linux Kernel Flow API
 *
 * Copyright (C) 2015  Netronome.
 *
 * Contacts: Simon Horman <simon.horman@netronome.com>
 *
 * Based in part on if_flow.h
 *
 * Copyright (c) 2014 John Fastabend <john.r.fastabend@intel.com>
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

#ifndef _FLOW_TABLE_TYPES_H
#define _FLOW_TABLE_TYPES_H

#include <linux/if_flow.h>

/**
 * @struct net_flow_action_arg
 * @brief encodes action arguments in structures one per argument
 *
 * @name    string identifier for pretty printing
 * @type    type of argument either u8, u16, u32, u64
 * @value_# indicate value/mask value type on of u8, u16, u32, or u64
 */
struct net_flow_action_arg {
	char *name;
	enum net_flow_action_arg_type type;
	union {
		__u8  value_u8;
		__u16 value_u16;
		__u32 value_u32;
		__u64 value_u64;
	};
};

/**
 * @struct net_flow_action
 * @brief a description of a endpoint defined action
 *
 * @name printable name
 * @uid unique action identifier
 * @types NET_FLOW_ACTION_TYPE_NULL terminated list of action types
 */
struct net_flow_action {
	char *name;
	int uid;
	struct net_flow_action_arg *args;
};

/**
 * @struct net_flow_field_ref
 * @brief uniquely identify field as instance:header:field tuple
 *
 * @instance identify unique instance of field reference
 * @header   identify unique header reference
 * @field    identify unique field in above header reference
 * @mask_type indicate mask type
 * @type     indicate value/mask value type on of u8, u16, u32, or u64
 * @value_u# value of field reference
 * @mask_u#  mask value of field reference
 */
struct net_flow_field_ref {
	int instance;
	int header;
	int field;
	int mask_type;
	int type;
	union {
		struct {
			__u8 value_u8;
			__u8 mask_u8;
		};
		struct {
			__u16 value_u16;
			__u16 mask_u16;
		};
		struct {
			__u32 value_u32;
			__u32 mask_u32;
		};
		struct {
			__u64 value_u64;
			__u64 mask_u64;
		};
	};
};

/**
 * @struct net_flow_rule
 * @brief describes the match/action entry
 *
 * @uid unique identifier for flow
 * @priority priority to execute flow match/action in table
 * @match null terminated set of match uids match criteria
 * @actoin null terminated set of action uids to apply to match
 *
 * Flows must match all entries in match set.
 */
struct net_flow_rule {
	int table_id;
	int uid;
	int priority;
	struct net_flow_field_ref *matches;
	struct net_flow_action *actions;
};

#endif
