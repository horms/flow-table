/* Based on:
 *
 * net/core/net_flow.c - Flow table interface for Switch devices
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
 */

#include <lib/nla-policy.h>

struct nla_policy net_flow_action_policy[NET_FLOW_ACTION_ATTR_MAX + 1] = {
	[NET_FLOW_ACTION_ATTR_NAME]	= {.type = NLA_STRING,
		                           .maxlen = NET_FLOW_NAMSIZ - 1 },
	[NET_FLOW_ACTION_ATTR_UID]	= {.type = NLA_U32 },
	[NET_FLOW_ACTION_ATTR_SIGNATURE]= {.type = NLA_NESTED },
};

struct nla_policy net_flow_act_policy[NET_FLOW_ACTION_MAX + 1] = {
        [NET_FLOW_ACTION]	= { .type = NLA_NESTED },
};

struct nla_policy net_flow_flow_policy[NET_FLOW_ATTR_MAX + 1] = {
        [NET_FLOW_ATTR_ERROR]	= { .type = NLA_U32 },
        [NET_FLOW_ATTR_TABLE]	= { .type = NLA_U32 },
        [NET_FLOW_ATTR_UID]	= { .type = NLA_U32 },
        [NET_FLOW_ATTR_PRIORITY]= { .type = NLA_U32 },
        [NET_FLOW_ATTR_MATCHES]	= { .type = NLA_NESTED },
        [NET_FLOW_ATTR_ACTIONS]	= { .type = NLA_NESTED },
};

struct nla_policy net_flow_net_flow_policy[NET_FLOW_NET_FLOW_MAX + 1] =
{
	[NET_FLOW_FLOW]	= { .type = NLA_NESTED },
};

struct nla_policy net_flow_policy[NET_FLOW_MAX + 1] =
{
	[NET_FLOW_IDENTIFIER_TYPE]	= { .type = NLA_U32 },
	[NET_FLOW_IDENTIFIER]		= { .type = NLA_U32 },
	[NET_FLOW_TABLES]		= { .type = NLA_NESTED },
	[NET_FLOW_HEADERS]		= { .type = NLA_NESTED },
	[NET_FLOW_ACTIONS]		= { .type = NLA_NESTED },
	[NET_FLOW_HEADER_GRAPH]		= { .type = NLA_NESTED },
	[NET_FLOW_TABLE_GRAPH]		= { .type = NLA_NESTED },
	[NET_FLOW_FLOWS]		= { .type = NLA_NESTED },
	[NET_FLOW_FLOWS_ERROR]		= { .type = NLA_NESTED },
};

struct nla_policy net_flow_field_ref_policy[NET_FLOW_FIELD_REF_MAX + 1] = {
        [NET_FLOW_FIELD_REF]	= { .minlen = sizeof(struct net_flow_field_ref) },
};

struct nla_policy net_flow_action_arg_policy[NET_FLOW_ACTION_ARG_MAX + 1] = {
        [NET_FLOW_ACTION_ARG]	= { .minlen = sizeof(struct net_flow_action_arg) },
};

struct nla_policy net_flow_table_flows_policy[NET_FLOW_TABLE_FLOWS_MAX + 1] = {
        [NET_FLOW_TABLE_FLOWS_TABLE]   = { .type = NLA_U32,},
        [NET_FLOW_TABLE_FLOWS_MINPRIO] = { .type = NLA_U32,},
        [NET_FLOW_TABLE_FLOWS_MAXPRIO] = { .type = NLA_U32,},
        [NET_FLOW_TABLE_FLOWS_FLOWS]   = { .type = NLA_NESTED,},
};
