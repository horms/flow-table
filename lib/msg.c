/* Baed in part by flow_table.c by John Fastabend */

#include <limits.h>
#include <stdlib.h>

#include <netlink/attr.h>
#include <netlink/genl/genl.h>
#include <netlink/msg.h>

#include <flow-table/data.h>
#include <flow-table/msg.h>

int
flow_table_put_field_ref(struct nl_msg *msg,
			  const struct net_flow_field_ref *ref)
{
	return nla_put(msg, NET_FLOW_FIELD_REF, sizeof *ref, ref);
}

int
flow_table_put_field_refs(struct nl_msg *msg,
			  const struct net_flow_field_ref *refs)
{
	int i;

	for (i = 0; refs[i].header; i++)
		if (flow_table_put_field_ref(msg, &refs[i]))
			return -1;

	return 0;
}

int
flow_table_put_action_arg(struct nl_msg *msg,
			  const struct net_flow_action_arg *arg)
{
	return nla_put(msg, NET_FLOW_ACTION_ARG, sizeof *arg, arg);
}

int
flow_table_put_action_args(struct nl_msg *msg,
			   const struct net_flow_action_arg *args)
{
	int i;

	for (i = 0; args[i].type; i++)
		if (flow_table_put_action_arg(msg, &args[i]))
			return -1;

	return 0;
}

int
flow_table_put_action(struct nl_msg *msg, const struct net_flow_action *action)
{
	struct nlattr *action_start;
	struct nlattr *sigs_start;

	action_start = nla_nest_start(msg, NET_FLOW_ACTION);
	if (!action_start)
		return -1;

	if (action->name &&
	    nla_put_string(msg, NET_FLOW_ACTION_ATTR_NAME, action->name))
		goto err;

	if (nla_put_u32(msg, NET_FLOW_ACTION_ATTR_UID, action->uid))
		goto err;


	sigs_start = nla_nest_start(msg, NET_FLOW_ACTION_ATTR_SIGNATURE);
	if (!sigs_start)
		goto err;

	if (flow_table_put_action_args(msg, action->args)) {
		nla_nest_cancel(msg, sigs_start);
		goto err;
	}

	nla_nest_end(msg, sigs_start);
	nla_nest_end(msg, action_start);
	return 0;

err:
	nla_nest_cancel(msg, action_start);
	return -1;
}

int
flow_table_put_actions(struct nl_msg *msg,
		       const struct net_flow_action *actions)
{
	int i;

	for (i = 0; actions[i].uid; i++)
		if (flow_table_put_action(msg, &actions[i]))
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

		err = flow_table_put_actions(msg, flow->actions);
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

int
flow_table_put_flows_desc(struct nl_msg *msg, int table,
			  int min_prio, int max_prio)
{
	struct nlattr *start;

	start = nla_nest_start(msg, NET_FLOW_FLOWS);
	if (!start)
		return -1;

	if (nla_put_u32(msg, NET_FLOW_TABLE_FLOWS_TABLE, table))
		goto err;

	if (min_prio >= 0 &&
	    nla_put_u32(msg, NET_FLOW_TABLE_FLOWS_MINPRIO, min_prio))
		goto err;

	if (max_prio >= 0 &&
	    nla_put_u32(msg, NET_FLOW_TABLE_FLOWS_MAXPRIO, max_prio))
		goto err;

	nla_nest_end(msg, start);

	return 0;
err:
	nla_nest_cancel(msg, start);
	return -1;
}

int
flow_table_put_flows(struct nl_msg *msg,
		     int (*cb)(struct nl_msg *msg, void *data),
		     void *cb_data)
{
	int err;
	struct nlattr *start;

	start = nla_nest_start(msg, NET_FLOW_FLOWS);
	if (!start)
		return -1;

	err = cb(msg, cb_data);
	if (err) {
		nla_nest_cancel(msg, start);
		return -1;
	}

	nla_nest_end(msg, start);
	return 0;
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
	int err;
	struct nl_msg *msg;

	msg = flow_table_msg_put(family, ifindex,
				 NET_FLOW_TABLE_CMD_GET_FLOWS);

	err = flow_table_put_flows_desc(msg, table, min_prio, max_prio);
	if (err) {
		free(msg);
		return NULL;
	}

	return msg;
}

struct nl_msg *
flow_table_msg_put_set_flows_request(int family, int ifindex,
				     int (*cb)(struct nl_msg *msg, void *data),
				     void *cb_data)
{
	int err;
	struct nl_msg *msg;

	msg = flow_table_msg_put(family, ifindex,
				 NET_FLOW_TABLE_CMD_SET_FLOWS);

	err = flow_table_put_flows(msg, cb, cb_data);
	if (err) {
		free(msg);
		return NULL;
	}

	return msg;
}

int
flow_table_get_ifindex(struct nlattr **attrs)
{
	uint32_t ifindex, type;

	if (!attrs || !attrs[NET_FLOW_IDENTIFIER_TYPE] ||
	    !attrs[NET_FLOW_IDENTIFIER])
		return -1;

	type = nla_get_u32(attrs[NET_FLOW_IDENTIFIER_TYPE]);
	ifindex = nla_get_u32(attrs[NET_FLOW_IDENTIFIER]);

	if (type != NET_FLOW_IDENTIFIER_IFINDEX || ifindex > INT_MAX)
		return -1;

	return ifindex;
}

static struct nla_policy net_flow_table_flows_policy[NET_FLOW_TABLE_FLOWS_MAX + 1] = {
        [NET_FLOW_TABLE_FLOWS_TABLE]   = { .type = NLA_U32,},
        [NET_FLOW_TABLE_FLOWS_MINPRIO] = { .type = NLA_U32,},
        [NET_FLOW_TABLE_FLOWS_MAXPRIO] = { .type = NLA_U32,},
        [NET_FLOW_TABLE_FLOWS_FLOWS]   = { .type = NLA_NESTED,},
};

int
flow_table_get_table_flows(struct nlattr *attr, int *table, int *min_prio,
			   int *max_prio)
{
	int err;
	struct nlattr *attrs[NET_FLOW_TABLE_FLOWS_MAX + 1];
	uint32_t utable, umin_prio, umax_prio;

	if (!attr)
		return -1;

	err = nla_parse_nested(attrs, NET_FLOW_TABLE_FLOWS_MAX, attr,
                               net_flow_table_flows_policy);
        if (err)
		return -1;

	if (!attrs[NET_FLOW_TABLE_FLOWS_TABLE])
		return -1;

	utable = nla_get_u32(attrs[NET_FLOW_TABLE_FLOWS_TABLE]);
	if (utable > INT_MAX)
		return -1;
	else
		*table = utable;

        if (attrs[NET_FLOW_TABLE_FLOWS_MINPRIO]) {
                umin_prio = nla_get_u32(attrs[NET_FLOW_TABLE_FLOWS_MINPRIO]);
		if (umin_prio > INT_MAX)
			return -1;
		else
			*min_prio = umin_prio;
	} else {
		*min_prio = -1;
	}
        if (attrs[NET_FLOW_TABLE_FLOWS_MAXPRIO]) {
                umax_prio = nla_get_u32(attrs[NET_FLOW_TABLE_FLOWS_MAXPRIO]);
		if (umax_prio > INT_MAX)
			return -1;
		else
			*max_prio = umax_prio;
	} else {
		*max_prio = -1;
	}

	return 0;
}

int
flow_table_get_field_ref(struct net_flow_field_ref *ref, struct nlattr *attr)
{
	if (nla_type(attr) != NET_FLOW_FIELD_REF)
		return -1;

	if (nla_len(attr) < (int)sizeof(struct net_flow_field_ref))
		return -1;

	*ref = *(struct net_flow_field_ref *) nla_data(attr);
	return 0;
}

struct net_flow_field_ref *
flow_table_get_field_refs(struct nlattr *attr)
{
	int count, rem;
	struct nlattr *a;
	struct net_flow_field_ref *refs;

	count = 0;
	nla_for_each_nested(a, attr, rem)
		count++;

	refs = calloc(count + 1, sizeof *refs);

	count = 0;
	nla_for_each_nested(a, attr, rem) {
		if (flow_table_get_field_ref(&refs[count++], a)) {
			free(refs);
			return NULL;
		}
	}

	return refs;
}

int
flow_table_get_action_arg(struct net_flow_action_arg *arg, struct nlattr *attr)
{
	if (nla_type(attr) != NET_FLOW_ACTION_ARG)
		return -1;

	if (nla_len(attr) < (int)sizeof(struct net_flow_action_arg))
		return -1;

	*arg = *(struct net_flow_action_arg *) nla_data(attr);
	return 0;
}

static struct nla_policy net_flow_action_policy[NET_FLOW_ACTION_ATTR_MAX + 1] = {
	[NET_FLOW_ACTION_ATTR_NAME]	= {.type = NLA_STRING,
					   .maxlen = NET_FLOW_NAMSIZ - 1 },
	[NET_FLOW_ACTION_ATTR_UID]	= {.type = NLA_U32 },
	[NET_FLOW_ACTION_ATTR_SIGNATURE]= {.type = NLA_NESTED },
};

int
flow_table_get_action(struct nlattr *attr, struct net_flow_action *action)
{
	int count, err, rem;
	struct nlattr *a;
	struct nlattr *attrs[NET_FLOW_ACTION_ATTR_MAX + 1];

	err = nla_parse_nested(attrs, NET_FLOW_ACTION_ATTR_MAX,
			       attr, net_flow_action_policy);
	if (err < 0)
		return -1;

        if (!attrs[NET_FLOW_ACTION_ATTR_UID] ||
            !attrs[NET_FLOW_ACTION_ATTR_SIGNATURE])
                return -1;

        action->uid = nla_get_u32(attrs[NET_FLOW_ACTION_ATTR_UID]);

	if (attrs[NET_FLOW_ACTION_ATTR_NAME]) {
		const char *name;

		name = nla_get_string(attrs[NET_FLOW_ACTION_ATTR_NAME]);
		if (strlen(name) >= NET_FLOW_NAMSIZ)
			return -1;
		strcpy(action->name, name);
	}

	count = 0;
	nla_for_each_nested(a, attrs[NET_FLOW_ACTION_ATTR_SIGNATURE], rem)
		if (nla_type(a) == NET_FLOW_ACTION_ARG)
			count++;

	action->args = calloc(count + 1, sizeof *action->args);

	count = 0;
	nla_for_each_nested(a, attrs[NET_FLOW_ACTION_ATTR_SIGNATURE], rem) {
		if (nla_type(a) != NET_FLOW_ACTION_ARG)
			continue;

		if (flow_table_get_action_arg(&action->args[count++], a)) {
			free(action->args);
			return -1;
		}
	}

	return 0;
}

struct net_flow_action *
flow_table_get_actions(struct nlattr *attr)
{
	int count, rem;
	struct nlattr *a;
	struct net_flow_action *actions;

	count = 0;
	nla_for_each_nested(a, attr, rem)
		count++;

	actions = calloc(count + 1, sizeof *actions);

	count = 0;
	nla_for_each_nested(a, attr, rem) {
		if (flow_table_get_action(a, actions + count++)) {
			flow_table_free_actions(actions);
			return NULL;
		}
	}

	return actions;
}

static struct nla_policy net_flow_flow_policy[NET_FLOW_ATTR_MAX + 1] = {
        [NET_FLOW_ATTR_ERROR]	= { .type = NLA_U32 },
        [NET_FLOW_ATTR_TABLE]	= { .type = NLA_U32 },
        [NET_FLOW_ATTR_UID]	= { .type = NLA_U32 },
        [NET_FLOW_ATTR_PRIORITY]= { .type = NLA_U32 },
        [NET_FLOW_ATTR_MATCHES]	= { .type = NLA_NESTED },
        [NET_FLOW_ATTR_ACTIONS]	= { .type = NLA_NESTED },
};

int
flow_table_get_flow(struct nlattr *attr, struct net_flow_flow *flow)
{
	int err;
	struct nlattr *attrs[NET_FLOW_ATTR_MAX + 1];


	err = nla_parse_nested(attrs, NET_FLOW_ATTR_MAX, attr,
			       net_flow_flow_policy);
	if (err)
		return -1;

        if (!attrs[NET_FLOW_ATTR_TABLE] || !attrs[NET_FLOW_ATTR_UID] ||
            !attrs[NET_FLOW_ATTR_PRIORITY])
                return -1;

        flow->table_id = nla_get_u32(attrs[NET_FLOW_ATTR_TABLE]);
        flow->uid = nla_get_u32(attrs[NET_FLOW_ATTR_UID]);
        flow->priority = nla_get_u32(attrs[NET_FLOW_ATTR_PRIORITY]);

        flow->matches = NULL;
        flow->actions = NULL;

        if (attrs[NET_FLOW_ATTR_MATCHES]) {
		flow->matches = flow_table_get_field_refs(attrs[NET_FLOW_ATTR_MATCHES]);
		if (!flow->matches)
			return -1;
        }

        if (attrs[NET_FLOW_ATTR_ACTIONS]) {
		flow->actions = flow_table_get_actions(attrs[NET_FLOW_ATTR_ACTIONS]);
		if (!flow->actions) {
			free(flow->matches);
			return -1;
		}
        }

        return 0;
}

int
flow_table_get_flow_flows(struct nlattr *attr,
			  int (*cb)(const struct net_flow_flow *flow,
				    void *data),
			  void *cb_data)
{
	int err, rem;
	struct nlattr *a;

	nla_for_each_nested(a, attr, rem) {
		struct net_flow_flow flow;

		if (nla_type(a) != NET_FLOW_FLOW)
			continue;

		err = flow_table_get_flow(a, &flow);
		if (err)
			return -1;

		err = cb(&flow, cb_data);

		free(flow.matches);
		flow_table_free_actions(flow.actions);

		if (err)
			return -1;
	}

	return 0;
}

static struct nla_policy net_flow_policy[NET_FLOW_MAX + 1] =
{
	[NET_FLOW_IDENTIFIER_TYPE]	= { .type = NLA_U32 },
	[NET_FLOW_IDENTIFIER]		= { .type = NLA_U32 },
	[NET_FLOW_TABLES]		= { .type = NLA_NESTED },
	[NET_FLOW_HEADERS]		= { .type = NLA_NESTED },
	[NET_FLOW_ACTIONS]		= { .type = NLA_NESTED },
	[NET_FLOW_HEADER_GRAPH]		= { .type = NLA_NESTED },
	[NET_FLOW_TABLE_GRAPH]		= { .type = NLA_NESTED },
	[NET_FLOW_FLOWS]		= { .type = NLA_NESTED },
	[NET_FLOW_FLOWS_ERROR]		= { .type = NLA_NESTED },
};

int
flow_table_get_get_flows_request(struct nlattr *attr, int *table,
				 int *max_prio, int *min_prio)
{
	int err;
	struct nlattr *attrs[NET_FLOW_MAX+1];
	int ifindex;

	if (!attr)
		return -1;

	err = nla_parse_nested(attrs, NET_FLOW_MAX, attr, net_flow_policy);
	if (err)
		return -1;

	ifindex = flow_table_get_ifindex(attrs);
	if (ifindex < 0)
		return -1;

	err = flow_table_get_table_flows(attrs[NET_FLOW_FLOWS], table,
					 max_prio, min_prio);
	if (err)
		return -1;

	return ifindex;
}

int
flow_table_get_set_flows_request(struct nlattr *attr,
				 int (*cb)(const struct net_flow_flow *flow,
					   void *data),
				 void *cb_data)
{
	int err;
	struct nlattr *attrs[NET_FLOW_MAX+1];
	int ifindex;

	if (!attr)
		return -1;

	err = nla_parse_nested(attrs, NET_FLOW_MAX, attr, net_flow_policy);
	if (err)
		return -1;

	ifindex = flow_table_get_ifindex(attrs);
	if (ifindex < 0)
		return -1;

	err = flow_table_get_flow_flows(attrs[NET_FLOW_FLOWS], cb, cb_data);
	if (err)
		return -1;

	return ifindex;
}
