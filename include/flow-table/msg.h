#ifndef FLOW_TABLE_MSG_H
#define FLOW_TABLE_MSG_H

#include <netlink/netlink.h>

#include <flow-table/types.h>

int
flow_table_put_field_ref(struct nl_msg *msg,
			  const struct net_flow_field_ref *ref);

int
flow_table_put_field_refs(struct nl_msg *msg,
			  const struct net_flow_field_ref *refs);

int
flow_table_put_action_arg(struct nl_msg *msg,
			  const struct net_flow_action_arg *arg);

int
flow_table_put_action_args(struct nl_msg *msg,
			   const struct net_flow_action_arg *args);

int
net_flow_put_action(struct nl_msg *msg, struct net_flow_action *action);

int
flow_table_put_actions(struct nl_msg *msg,
		       const struct net_flow_action *actions);

int
flow_table_put_flow(struct nl_msg *msg, const struct net_flow_rule *flow);

int
flow_table_put_flows_desc(struct nl_msg *msg, int table,
			  int min_prio, int max_prio);

int
flow_table_put_flows(struct nl_msg *msg,
		     int (*cb)(struct nl_msg *msg, void *data),
		     void *cb_data);

struct nl_msg *
flow_table_msg_put(int family, int ifindex, int cmd);

struct nl_msg *
flow_table_msg_put_get_flows_request(int family, int ifindex, int table,
				     int min_prio, int max_prio);

struct nl_msg *
flow_table_msg_put_set_flows_request(int family, int ifindex,
				     int (*cb)(struct nl_msg *msg, void *data),
				     void *cb_data);

int
flow_table_get_ifindex(struct nlattr **attrs);

int
flow_table_get_table_flows(struct nlattr *attr, int *table, int *min_prio,
			   int *max_prio);

int
flow_table_get_field_ref(struct net_flow_field_ref *ref, struct nlattr *attr);

struct net_flow_field_ref *
flow_table_get_field_refs(struct nlattr *attr);

int
flow_table_get_action_arg(struct net_flow_action_arg *arg, struct nlattr *attr);

int
flow_table_get_action(struct nlattr *attr, struct net_flow_action *action);

struct net_flow_action *
flow_table_get_actions(struct nlattr *attr);

int
flow_table_get_flow(struct nlattr *attr, struct net_flow_rule *flow);

int
flow_table_get_flow_flows(struct nlattr *attr,
			  int (*cb)(const struct net_flow_rule *flow,
				    void *data),
			  void *cb_data);
int
flow_table_get_ifindex_from_request(struct nlattr *attr);

int
flow_table_get_get_flows_request(struct nlattr *attr, int *table,
				 int *max_prio, int *min_prio);

int
flow_table_flows_request(struct nlattr *attr,
			 int (*cb)(const struct net_flow_rule *flow,
				   void *data),
			 void *cb_data);
#endif
