#ifndef FLOW_TABLE_NLA_POLICY_H
#define FLOW_TABLE_NLA_POLICY_H

#include <netlink/attr.h>
#include <linux/if_flow.h>

/* Missing from if_flow.h */
#ifndef NFL_JUMP_ENTRY_MAX
#define NFL_JUMP_ENTRY_MAX (__NFL_JUMP_ENTRY_MAX - 1)
#endif

extern struct nla_policy flow_table_action_policy[NFL_ACTION_ATTR_MAX + 1];
extern struct nla_policy flow_table_act_policy[NFL_ACTION_MAX + 1];
extern struct nla_policy flow_table_rule_policy[NFL_ATTR_MAX + 1];
extern struct nla_policy flow_table_rule_policy__[NFL_NFL_MAX + 1];
extern struct nla_policy flow_table_policy[NFL_MAX + 1];
extern struct nla_policy flow_table_field_ref_policy[NFL_FIELD_REF_MAX + 1];
extern struct nla_policy flow_table_field_refs_policy[NFL_FIELD_REFS_MAX + 1];
extern struct nla_policy flow_table_action_arg_policy[NFL_ACTION_ARG_MAX + 1];
extern struct nla_policy flow_table_action_args_policy[NFL_ACTION_ARGS_MAX + 1];
extern struct nla_policy flow_table_table_attr_policy[NFL_TABLE_ATTR_MAX + 1];
extern struct nla_policy flow_table_table_policy[NFL_TABLE_MAX + 1];
extern struct nla_policy flow_table_field_attr_policy[NFL_FIELD_ATTR_MAX + 1];
extern struct nla_policy flow_table_field_policy[NFL_FIELD_MAX + 1];
extern struct nla_policy flow_table_header_attr_policy[NFL_HEADER_ATTR_MAX + 1];
extern struct nla_policy flow_table_header_policy[NFL_HEADER_MAX + 1];
extern struct nla_policy flow_table_jump_entry_policy[NFL_JUMP_ENTRY_MAX + 1];
extern struct nla_policy flow_table_header_node_hdrs_policy[NFL_HEADER_NODE_HDRS_MAX + 1];
extern struct nla_policy flow_table_header_node_policy[NFL_HEADER_NODE_MAX + 1];
extern struct nla_policy flow_table_header_graph_policy[NFL_HEADER_GRAPH_MAX + 1];
extern struct nla_policy flow_table_table_graph_node_policy[NFL_TABLE_GRAPH_NODE_MAX + 1];
extern struct nla_policy flow_table_table_graph_policy[NFL_TABLE_GRAPH_MAX + 1];
extern struct nla_policy flow_table_table_flows_policy[NFL_TABLE_FLOWS_MAX + 1];

#endif
