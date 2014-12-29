/* Baed in part by flow_table.c by John Fastabend */

#include <stdlib.h>

#include <netlink/attr.h>
#include <netlink/genl/genl.h>
#include <netlink/msg.h>

#include <flow-table/msg.h>

int
flow_table_put_field_refs(struct nl_msg *msg,
			  const struct net_flow_field_ref *refs)
{
	int i;

	for (i = 0; refs[i].header; i++)
		if (nla_put(msg, NET_FLOW_FIELD_REF, sizeof refs[i], &refs[i]))
			return -1;

	return 0;
}

int
flow_table_put_flow_action_args(struct nl_msg *msg,
				const struct net_flow_action_arg *args)
{
	int i;

	for (i = 0; args[i].type; i++) {
		if (nla_put(msg, NET_FLOW_ACTION_ARG, sizeof args[i], &args[i]))
			return -1;
	}

	return 0;
}

int
flow_table_put_flow_action(struct nl_msg *msg,
			   const struct net_flow_action *action)
{
	struct nlattr *start;
	int i;

	start = nla_nest_start(msg, NET_FLOW_ACTION);
	if (!start)
		return -1;

	if (nla_put_u32(msg, NET_FLOW_ACTION_ATTR_UID, action->uid))
		goto err;

	for (i = 0; action[i].uid; i++) {
		struct nlattr *sigs;

		sigs = nla_nest_start(msg, NET_FLOW_ACTION_ATTR_SIGNATURE);
		if (!sigs)
			goto err;

		if (flow_table_put_flow_action_args(msg, action[i].args)) {
			nla_nest_cancel(msg, sigs);
			goto err;
		}
		nla_nest_end(msg, sigs);
	}

	nla_nest_end(msg, start);
	return 0;

err:
	nla_nest_cancel(msg, start);
	return -1;
}

int
flow_table_put_flow_actions(struct nl_msg *msg,
			    const struct net_flow_action *actions)
{
	int i;

	for (i = 0; actions[i].uid; i++)
		if (flow_table_put_flow_action(msg, &actions[i]))
			return -1;

	return 0;
}

int
flow_table_put_flow(struct nl_msg *msg, const struct net_flow_flow *flow)
{
	int err;
	struct nlattr *start;

	start = nla_nest_start(msg, NET_FLOW_FLOW);
	if (!start)
		return -1;

	if (nla_put_u32(msg, NET_FLOW_ATTR_TABLE, flow->table_id) ||
	    nla_put_u32(msg, NET_FLOW_ATTR_UID, flow->uid) ||
	    nla_put_u32(msg, NET_FLOW_ATTR_PRIORITY, flow->priority)) {
		nla_nest_cancel(msg, start);
		return -1;
	}

	if (flow->matches) {
		struct nlattr *matches;

		matches = nla_nest_start(msg, NET_FLOW_ATTR_MATCHES);
		if (!matches)
			goto err;

		err = flow_table_put_field_refs(msg, flow->matches);
		if (err) {
			nla_nest_cancel(msg, matches);
			goto err;
		}

		nla_nest_end(msg, matches);
	}


	if (flow->actions) {
		struct nlattr *actions;

		actions = nla_nest_start(msg, NET_FLOW_ATTR_ACTIONS);
		if (!actions)
			goto err;

		err = flow_table_put_flow_actions(msg, flow->actions);
		if (err) {
			nla_nest_cancel(msg, actions);
			goto err;
		}

		nla_nest_end(msg, actions);
	}

	nla_nest_end(msg, start);
	return 0;

err:
	nla_nest_cancel(msg, start);
	return -1;
}

struct nl_msg *
flow_table_msg_put(int family, int ifindex, int cmd)
{
	struct nl_msg *msg;

	msg = nlmsg_alloc();
	if (!msg)
		return NULL;

	if (!genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, family,
			 0, 0, cmd, NET_FLOW_GENL_VERSION) ||
	    nla_put_u32(msg, NET_FLOW_IDENTIFIER_TYPE,
			 NET_FLOW_IDENTIFIER_IFINDEX) ||
	    nla_put_u32(msg, NET_FLOW_IDENTIFIER, ifindex)) {
		free(msg);
		return NULL;
	}

	return msg;
}

struct nl_msg *
flow_table_msg_put_get_flows_request(int family, int ifindex, int table,
				     int min_prio, int max_prio)
{
	struct nl_msg *msg;
	struct nlattr *start;

	msg = flow_table_msg_put(family, ifindex,
				 NET_FLOW_TABLE_CMD_GET_FLOWS);

	start = nla_nest_start(msg, NET_FLOW_FLOWS);
	if (!start)
		goto err_msg;

	if (nla_put_u32(msg, NET_FLOW_TABLE_FLOWS_TABLE, table))
		goto err_nest;

	if (min_prio >= 0 &&
	    nla_put_u32(msg, NET_FLOW_TABLE_FLOWS_MINPRIO, min_prio))
		goto err_nest;

	if (max_prio >= 0 &&
	    nla_put_u32(msg, NET_FLOW_TABLE_FLOWS_MAXPRIO, max_prio))
		goto err_nest;

	nla_nest_end(msg, start);

	return msg;

err_nest:
	nla_nest_cancel(msg, start);
err_msg:
	free(msg);
	return NULL;
}

struct nl_msg *
flow_table_msg_put_set_flows_request(int family, int ifindex,
				     int (*cb)(struct nl_msg *msg, void *data),
				     void *cb_data)
{
	int err;
	struct nl_msg *msg;
	struct nlattr *start;

	msg = flow_table_msg_put(family, ifindex,
				 NET_FLOW_TABLE_CMD_SET_FLOWS);

	start = nla_nest_start(msg, NET_FLOW_FLOWS);
	if (!start)
		goto err_msg;

	err = cb(msg, cb_data);
	if (err)
		goto err_nest;

	nla_nest_end(msg, start);

	return msg;

err_nest:
	nla_nest_cancel(msg, start);
err_msg:
	free(msg);
	return NULL;
}
