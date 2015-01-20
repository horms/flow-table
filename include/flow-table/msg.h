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
