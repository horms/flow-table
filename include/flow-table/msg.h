#ifndef FLOW_TABLE_MSG_H
#define FLOW_TABLE_MSG_H

#include <netlink/netlink.h>

#include <linux/if_flow.h>

int
flow_table_put_field_refs(struct nl_msg *msg,
			  const struct net_flow_field_ref *refs);

int
flow_table_put_action_args(struct nl_msg *msg,
			   struct net_flow_action_arg *args);

int
net_flow_put_flow_action(struct nl_msg *msg,
			 struct net_flow_action *action);

int
flow_table_put_actions(struct nl_msg *msg,
		       const struct net_flow_action *actions);

int
flow_table_put_flow(struct nl_msg *msg, const struct net_flow_flow *flow);

struct nl_msg *
flow_table_msg_put(int family, int ifindex, int cmd);

struct nl_msg *
flow_table_msg_put_get_flows_request(int family, int ifindex, int table,
				     int min_prio, int max_prio);

struct nl_msg *
flow_table_msg_put_set_flows_request(int family, int ifindex,
				     int (*cb)(struct nl_msg *msg, void *data),
				     void *cb_data);

#endif
