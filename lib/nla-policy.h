#ifndef FLOW_TABLE_NLA_POLICY_H
#define FLOW_TABLE_NLA_POLICY_H

#include <netlink/attr.h>
#include <linux/if_flow.h>

extern struct nla_policy net_flow_action_policy[NET_FLOW_ACTION_ATTR_MAX + 1];
extern struct nla_policy net_flow_act_policy[NET_FLOW_ACTION_MAX + 1];
extern struct nla_policy net_flow_flow_policy[NET_FLOW_ATTR_MAX + 1];
extern struct nla_policy net_flow_net_flow_policy[NET_FLOW_NET_FLOW_MAX + 1];
extern struct nla_policy net_flow_policy[NET_FLOW_MAX + 1];
extern struct nla_policy net_flow_field_ref_policy[NET_FLOW_FIELD_REF_MAX + 1];
extern struct nla_policy net_flow_action_arg_policy[NET_FLOW_ACTION_ARG_MAX + 1];
extern struct nla_policy net_flow_table_flows_policy[NET_FLOW_TABLE_FLOWS_MAX + 1]; 

#endif
