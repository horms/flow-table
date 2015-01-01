#ifndef FLOW_TABLE_DATA_H
#define FLOW_TABLE_DATA_H

#include <sys/socket.h>

#include <linux/if_flow.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include <flow-table/data.h>

bool
flow_table_field_ref_cmp(const struct net_flow_field_ref *a,
		       const struct net_flow_field_ref *b);

bool
flow_table_field_refs_cmp(const struct net_flow_field_ref *a,
			const struct net_flow_field_ref *b);

struct net_flow_field_ref *
flow_table_field_refs_clone(struct net_flow_field_ref *refs);

struct net_flow_action_arg *
flow_table_action_arg_clone(struct net_flow_action_arg *args);

#include <flow-table/types.h>

void
flow_table_free_actions(struct net_flow_action *actions);

struct net_flow_action *
flow_table_flow_actions_clone(const struct net_flow_action *actions);

int
flow_table_flow_clone_data(struct net_flow_flow *dest,
			 const struct net_flow_flow *src);

#endif
