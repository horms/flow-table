/* Based on:
 *
 * net/core/flow_table.c - Flow table interface for Switch devices
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

#define VARINT_ATTR {			\
	.type = NLA_UNSPEC,		\
        .minlen = sizeof(uint8_t),	\
        .maxlen = sizeof(uint64_t),	\
}

struct nla_policy flow_table_action_policy[NFL_ACTION_ATTR_MAX + 1] = {
	[NFL_ACTION_ATTR_NAME]	= { .type = NLA_STRING },
	[NFL_ACTION_ATTR_UID]	= { .type = NLA_U32 },
	[NFL_ACTION_ATTR_SIGNATURE]= {.type = NLA_NESTED },
};

struct nla_policy flow_table_act_policy[NFL_ACTION_MAX + 1] = {
        [NFL_ACTION]		= { .type = NLA_NESTED },
};

struct nla_policy flow_table_field_ref_policy[NFL_FIELD_REF_MAX + 1] = {
	[NFL_FIELD_REF_NEXT_NODE] = { .type = NLA_U32,},
	[NFL_FIELD_REF_INSTANCE]  = { .type = NLA_U32,},
	[NFL_FIELD_REF_HEADER]	  = { .type = NLA_U32,},
	[NFL_FIELD_REF_FIELD]	  = { .type = NLA_U32,},
	[NFL_FIELD_REF_MASK_TYPE] = { .type = NLA_U32,},
	[NFL_FIELD_REF_TYPE]	  = { .type = NLA_U32,},
	[NFL_FIELD_REF_VALUE]	  = VARINT_ATTR,
	[NFL_FIELD_REF_MASK]	  = VARINT_ATTR,
};

struct nla_policy flow_table_field_refs_policy[NFL_FIELD_REFS_MAX + 1] = {
        [NFL_FIELD_REF]		= { .type = NLA_NESTED },
};

struct nla_policy flow_table_action_arg_policy[NFL_ACTION_ARG_MAX + 1] = {
	[NFL_ACTION_ARG_NAME]  = { .type = NLA_STRING },
	[NFL_ACTION_ARG_TYPE]  = { .type = NLA_U32 },
	[NFL_ACTION_ARG_VALUE] = VARINT_ATTR,
};

struct nla_policy flow_table_action_args_policy[NFL_ACTION_ARGS_MAX + 1] = {
        [NFL_ACTION_ARG]	= { .type = NLA_NESTED },
};

struct nla_policy flow_table_table_attr_policy[NFL_TABLE_ATTR_MAX + 1] =
{
	[NFL_TABLE_ATTR_NAME]		= { .type = NLA_STRING },
	[NFL_TABLE_ATTR_UID]		= { .type = NLA_U32 },
	[NFL_TABLE_ATTR_SOURCE]		= { .type = NLA_U32 },
	[NFL_TABLE_ATTR_APPLY]		= { .type = NLA_U32 },
	[NFL_TABLE_ATTR_SIZE]		= { .type = NLA_U32 },
	[NFL_TABLE_ATTR_MATCHES]	= { .type = NLA_NESTED },
	[NFL_TABLE_ATTR_ACTIONS]	= { .type = NLA_NESTED },
};

struct nla_policy flow_table_table_policy[NFL_TABLE_MAX + 1] =
{
	[NFL_TABLE]		= { .type = NLA_NESTED },
};

struct nla_policy flow_table_field_attr_policy[NFL_FIELD_ATTR_MAX + 1] =
{
	[NFL_FIELD_ATTR_NAME]		= { .type = NLA_STRING },
	[NFL_FIELD_ATTR_UID]		= { .type = NLA_U32 },
	[NFL_FIELD_ATTR_BITWIDTH]	= { .type = NLA_U32 },
};

struct nla_policy flow_table_field_policy[NFL_FIELD_MAX + 1] =
{
	[NFL_FIELD]		= { .type = NLA_NESTED },
};

struct nla_policy flow_table_header_attr_policy[NFL_HEADER_ATTR_MAX + 1] =
{
	[NFL_HEADER_ATTR_NAME]		= { .type = NLA_STRING },
	[NFL_HEADER_ATTR_UID]		= { .type = NLA_U32 },
	[NFL_HEADER_ATTR_FIELDS]	= { .type = NLA_NESTED },
};

struct nla_policy flow_table_header_policy[NFL_HEADER_MAX + 1] =
{
	[NFL_HEADER]		= { .type = NLA_NESTED },
};

struct nla_policy flow_table_jump_entry_policy[NFL_JUMP_ENTRY_MAX + 1] =
{
	[NFL_JUMP_ENTRY]		= { .type = NLA_NESTED },
};

struct nla_policy flow_table_header_node_hdrs_policy[NFL_HEADER_NODE_HDRS_MAX + 1] =
{
	[NFL_HEADER_NODE_HDRS_VALUE]	= { .type = NLA_U32 },
};

struct nla_policy flow_table_header_node_policy[NFL_HEADER_NODE_MAX + 1] =
{
	[NFL_HEADER_NODE_NAME]		= { .type = NLA_STRING },
	[NFL_HEADER_NODE_UID]		= { .type = NLA_U32 },
	[NFL_HEADER_NODE_HDRS]		= { .type = NLA_NESTED },
	[NFL_HEADER_NODE_JUMP]		= { .type = NLA_NESTED },
};

struct nla_policy flow_table_header_graph_policy[NFL_HEADER_GRAPH_MAX + 1] =
{
	[NFL_HEADER_GRAPH_NODE]		= { .type = NLA_NESTED },
};

struct nla_policy flow_table_table_graph_node_policy[NFL_TABLE_GRAPH_NODE_MAX + 1] =
{
	[NFL_TABLE_GRAPH_NODE_UID]	= { .type = NLA_U32 },
	[NFL_TABLE_GRAPH_NODE_FLAGS]	= { .type = NLA_U32 },
	[NFL_TABLE_GRAPH_NODE_JUMP]	= { .type = NLA_NESTED },
};

struct nla_policy flow_table_table_graph_policy[NFL_TABLE_GRAPH_MAX + 1] =
{
	[NFL_TABLE_GRAPH_NODE]		= { .type = NLA_NESTED },
};

struct nla_policy flow_table_table_flows_policy[NFL_TABLE_FLOWS_MAX + 1] = {
        [NFL_TABLE_FLOWS_TABLE]   = { .type = NLA_U32,},
        [NFL_TABLE_FLOWS_MINPRIO] = { .type = NLA_U32,},
        [NFL_TABLE_FLOWS_MAXPRIO] = { .type = NLA_U32,},
        [NFL_TABLE_FLOWS_FLOWS]   = { .type = NLA_NESTED,},
};

struct nla_policy flow_table_rule_policy[NFL_ATTR_MAX + 1] = {
        [NFL_ATTR_ERROR]	= { .type = NLA_U32 },
        [NFL_ATTR_TABLE]	= { .type = NLA_U32 },
        [NFL_ATTR_UID]		= { .type = NLA_U32 },
        [NFL_ATTR_PRIORITY]	= { .type = NLA_U32 },
        [NFL_ATTR_MATCHES]	= { .type = NLA_NESTED },
        [NFL_ATTR_ACTIONS]	= { .type = NLA_NESTED },
};

struct nla_policy flow_table_rule_policy__[NFL_NFL_MAX + 1] =
{
	[NFL_FLOW]		= { .type = NLA_NESTED },
};

struct nla_policy flow_table_policy[NFL_MAX + 1] =
{
	[NFL_IDENTIFIER_TYPE]	= { .type = NLA_U32 },
	[NFL_IDENTIFIER]	= { .type = NLA_U32 },
	[NFL_TABLES]		= { .type = NLA_NESTED },
	[NFL_HEADERS]		= { .type = NLA_NESTED },
	[NFL_ACTIONS]		= { .type = NLA_NESTED },
	[NFL_HEADER_GRAPH]	= { .type = NLA_NESTED },
	[NFL_TABLE_GRAPH]	= { .type = NLA_NESTED },
	[NFL_FLOWS]		= { .type = NLA_NESTED },
	[NFL_FLOWS_ERROR]	= { .type = NLA_NESTED },
};
