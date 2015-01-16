#ifndef FLOW_TABLE_NLA_POLICY_H
#define FLOW_TABLE_NLA_POLICY_H

#include <netlink/attr.h>
#include <linux/if_flow.h>

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
extern struct nla_policy flow_table_table_flows_policy[NFL_TABLE_FLOWS_MAX + 1];

#endif
