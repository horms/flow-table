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

#ifndef FLOW_TABLE_DATA_H
#define FLOW_TABLE_DATA_H

#include <sys/socket.h>

#include <linux/if_flow.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include <flow-table/data.h>
#include <flow-table/types.h>

bool
flow_table_field_refs_are_subset(const struct net_flow_field_ref *a,
                                 const struct net_flow_field_ref *b);

struct net_flow_field_ref *
flow_table_field_refs_clone(struct net_flow_field_ref *refs);

struct net_flow_action_arg *
flow_table_action_arg_clone(struct net_flow_action_arg *args);

void
flow_table_free_actions(struct net_flow_action *actions);

struct net_flow_action *
flow_table_actions_clone(const struct net_flow_action *actions);

int
flow_table_rule_clone_data(struct net_flow_rule *dest,
                           const struct net_flow_rule *src);

#endif
